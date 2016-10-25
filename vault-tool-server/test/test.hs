{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Data.Aeson
import Data.List (sort)
import GHC.Generics
import System.Environment
import System.IO.Temp (withSystemTempDirectory)
import Test.Tasty.HUnit

import Network.VaultTool
import Network.VaultTool.VaultServerProcess

withTempVaultBackend :: (VaultBackendConfig -> IO a) -> IO a
withTempVaultBackend action = withSystemTempDirectory "hs_vault" $ \tmpDir -> do
    let backendConfig = object
            [ "file" .= object
                [ "path" .= tmpDir
                ]
            ]
    action backendConfig

main :: IO ()
main = withTempVaultBackend $ \vaultBackendConfig -> do
    vaultExe <- lookupEnv "VAULT_EXE"

    let cfg = vaultConfigDefaultAddress vaultBackendConfig
        addr = vaultAddress cfg
    withVaultConfigFile cfg $ \vaultConfigFile ->
        withVaultServerProcess vaultExe vaultConfigFile addr $
            talkToVault addr

-- | The vault must be a newly created, non-initialized vault
--
-- TODO It would be better to break this into lots of individual unit tests
-- instead of this one big-ass test
talkToVault :: VaultAddress -> IO ()
talkToVault addr = do
    health <- vaultHealth addr
    _VaultHealth_Initialized health @?= False

    (unsealKeys, rootToken) <- vaultInit addr 4 2

    length unsealKeys @?= 4

    status0 <- vaultSealStatus addr
    status0 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 0
        }

    status1 <- vaultUnseal addr (VaultUnseal_Key (unsealKeys !! 0))
    status1 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 1
        }

    status2 <- vaultUnseal addr VaultUnseal_Reset
    status2 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 0
        }

    status3 <- vaultUnseal addr (VaultUnseal_Key (unsealKeys !! 1))
    status3 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 1
        }

    status4 <- vaultUnseal addr (VaultUnseal_Key (unsealKeys !! 2))
    status4 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = False
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 0
        }

    conn <- connectToVault addr rootToken
    allMounts <- vaultMounts conn

    fmap _VaultMount_Type (lookup "cubbyhole/" allMounts) @?= Just "cubbyhole"
    fmap _VaultMount_Type (lookup "secret/" allMounts) @?= Just "generic"
    fmap _VaultMount_Type (lookup "sys/" allMounts) @?= Just "system"

    _ <- vaultMountTune conn "cubbyhole"
    _ <- vaultMountTune conn "secret"
    _ <- vaultMountTune conn "sys"

    vaultNewMount conn "mymount" VaultMount
        { _VaultMount_Type = "generic"
        , _VaultMount_Description = Just "blah blah blah"
        , _VaultMount_Config = Just VaultMountConfig
            { _VaultMountConfig_DefaultLeaseTtl = Just 42
            , _VaultMountConfig_MaxLeaseTtl = Nothing
            }
        }

    mounts2 <- vaultMounts conn
    fmap _VaultMount_Description (lookup "mymount/" mounts2) @?= Just "blah blah blah"

    t <- vaultMountTune conn "mymount"
    _VaultMountConfig_DefaultLeaseTtl t @?= 42

    vaultMountSetTune conn "mymount" VaultMountConfig
        { _VaultMountConfig_DefaultLeaseTtl = Just 52
        , _VaultMountConfig_MaxLeaseTtl = Nothing
        }

    t2 <- vaultMountTune conn "mymount"
    _VaultMountConfig_DefaultLeaseTtl t2 @?= 52

    vaultUnmount conn "mymount"

    mounts3 <- vaultMounts conn
    lookup "mymount/" mounts3 @?= Nothing

    vaultWrite conn (VaultSecretPath "secret/big") (object ["A" .= 'a', "B" .= 'b'])

    (_, r) <- vaultRead conn (VaultSecretPath "secret/big")
    case r of
        Left err -> assertFailure $ "Failed to parse secret/big: " ++ (show err)
        Right x -> x @?= object ["A" .= 'a', "B" .= 'b']

    vaultWrite conn (VaultSecretPath "secret/fun") (FunStuff "fun" [1, 2, 3])
    (_, r2) <- vaultRead conn (VaultSecretPath "secret/fun")
    case r2 of
        Left err -> assertFailure $ "Failed to parse secret/big: " ++ (show err)
        Right x -> x @?= (FunStuff "fun" [1, 2, 3])

    (_, r3) <- vaultRead conn (VaultSecretPath "secret/big")
    case r3 of
        Left (v, _) -> v @?= object ["A" .= 'a', "B" .= 'b']
        Right (x :: FunStuff) -> assertFailure $ "Somehow parsed an impossible value" ++ show x

    vaultWrite conn (VaultSecretPath "secret/foo/bar/a") (object ["X" .= 'x'])
    vaultWrite conn (VaultSecretPath "secret/foo/bar/b") (object ["X" .= 'x'])
    vaultWrite conn (VaultSecretPath "secret/foo/bar/a/b/c/d/e/f/g") (object ["X" .= 'x'])
    vaultWrite conn (VaultSecretPath "secret/foo/quack/duck") (object ["X" .= 'x'])

    keys <- vaultList conn (VaultSecretPath "secret/")
    assertBool "Secret in list" $ VaultSecretPath "secret/big" `elem` keys
    vaultDelete conn (VaultSecretPath "secret/big")

    keys2 <- vaultList conn (VaultSecretPath "secret")
    assertBool "Secret not in list" $ not (VaultSecretPath "secret/big" `elem` keys2)

    keys3 <- vaultListRecursive conn (VaultSecretPath "secret/foo/")
    sort keys3 @?= sort
        [ VaultSecretPath "secret/foo/bar/a"
        , VaultSecretPath "secret/foo/bar/b"
        , VaultSecretPath "secret/foo/bar/a/b/c/d/e/f/g"
        , VaultSecretPath "secret/foo/quack/duck"
        ]

    vaultSeal conn

    status5 <- vaultSealStatus addr
    status5 @?= VaultSealStatus
        { _VaultSealStatus_Sealed = True
        , _VaultSealStatus_T = 2
        , _VaultSealStatus_N = 4
        , _VaultSealStatus_Progress = 0
        }

    health2 <- vaultHealth addr
    _VaultHealth_Initialized health2 @?= True
    _VaultHealth_Sealed health2 @?= True

data FunStuff = FunStuff
    { funString :: String
    , funNumbers :: [Int]
    }
    deriving (Show, Eq, Generic)

instance FromJSON FunStuff
instance ToJSON FunStuff
