{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Data.Aeson
import Data.List (sort)
import Data.Text (Text)
import GHC.Generics
import System.Environment
import System.IO.Temp (withSystemTempDirectory)
import Test.Tasty.HUnit

import Network.VaultTool
import Network.VaultTool.KeyValueV2
import Network.VaultTool.VaultServerProcess

withTempVaultBackend :: (VaultBackendConfig -> IO a) -> IO a
withTempVaultBackend action = withSystemTempDirectory "hs_vault" $ \tmpDir -> do
    let backendConfig =
            object
                [ "file"
                    .= object
                        [ "path" .= tmpDir
                        ]
                ]
    action backendConfig

main :: IO ()
main = withTempVaultBackend $ \vaultBackendConfig -> do
    putStrLn "Running tests..."

    vaultExe <- lookupEnv "VAULT_EXE"

    let cfg = vaultConfigDefaultAddress vaultBackendConfig
        addr = vaultAddress cfg
    withVaultConfigFile cfg $ \vaultConfigFile ->
        withVaultServerProcess vaultExe vaultConfigFile addr $
            talkToVault addr

    putStrLn "Ok"

{- | The vault must be a newly created, non-initialized vault

 TODO It would be better to break this into lots of individual unit tests
 instead of this one big-ass test
-}
talkToVault :: VaultAddress -> IO ()
talkToVault addr = do
    health <- vaultHealth addr
    _VaultHealth_Initialized health @?= False

    (unsealKeys, rootToken) <- vaultInit addr 4 2

    length unsealKeys @?= 4

    status0 <- vaultSealStatus addr
    status0
        @?= VaultSealStatus
            { _VaultSealStatus_Sealed = True
            , _VaultSealStatus_T = 2
            , _VaultSealStatus_N = 4
            , _VaultSealStatus_Progress = 0
            }

    status1 <- vaultUnseal addr (VaultUnseal_Key (unsealKeys !! 0))
    status1
        @?= VaultSealStatus
            { _VaultSealStatus_Sealed = True
            , _VaultSealStatus_T = 2
            , _VaultSealStatus_N = 4
            , _VaultSealStatus_Progress = 1
            }

    status2 <- vaultUnseal addr VaultUnseal_Reset
    status2
        @?= VaultSealStatus
            { _VaultSealStatus_Sealed = True
            , _VaultSealStatus_T = 2
            , _VaultSealStatus_N = 4
            , _VaultSealStatus_Progress = 0
            }

    status3 <- vaultUnseal addr (VaultUnseal_Key (unsealKeys !! 1))
    status3
        @?= VaultSealStatus
            { _VaultSealStatus_Sealed = True
            , _VaultSealStatus_T = 2
            , _VaultSealStatus_N = 4
            , _VaultSealStatus_Progress = 1
            }

    status4 <- vaultUnseal addr (VaultUnseal_Key (unsealKeys !! 2))
    status4
        @?= VaultSealStatus
            { _VaultSealStatus_Sealed = False
            , _VaultSealStatus_T = 2
            , _VaultSealStatus_N = 4
            , _VaultSealStatus_Progress = 0
            }

    conn <- connectToVault addr rootToken

    vaultNewMount
        conn
        "secret"
        VaultMount
            { _VaultMount_Type = "kv"
            , _VaultMount_Description = Just "key/value secret storage"
            , _VaultMount_Config = Nothing
            , _VaultMount_Options =
                Just
                    VaultMountOptions
                        { _VaultMountOptions_Version = Just 2
                        }
            }

    allMounts <- vaultMounts conn

    fmap _VaultMount_Type (lookup "cubbyhole/" allMounts) @?= Just "cubbyhole"
    fmap _VaultMount_Type (lookup "secret/" allMounts) @?= Just "kv"
    fmap _VaultMount_Type (lookup "sys/" allMounts) @?= Just "system"

    _ <- vaultMountTune conn "cubbyhole"
    _ <- vaultMountTune conn "secret"
    _ <- vaultMountTune conn "sys"

    vaultNewMount
        conn
        "mymount"
        VaultMount
            { _VaultMount_Type = "generic"
            , _VaultMount_Description = Just "blah blah blah"
            , _VaultMount_Config =
                Just
                    VaultMountConfig
                        { _VaultMountConfig_DefaultLeaseTtl = Just 42
                        , _VaultMountConfig_MaxLeaseTtl = Nothing
                        }
            , _VaultMount_Options = Nothing
            }

    mounts2 <- vaultMounts conn
    fmap _VaultMount_Description (lookup "mymount/" mounts2) @?= Just "blah blah blah"

    t <- vaultMountTune conn "mymount"
    _VaultMountConfig_DefaultLeaseTtl t @?= 42

    vaultMountSetTune
        conn
        "mymount"
        VaultMountConfig
            { _VaultMountConfig_DefaultLeaseTtl = Just 52
            , _VaultMountConfig_MaxLeaseTtl = Nothing
            }

    t2 <- vaultMountTune conn "mymount"
    _VaultMountConfig_DefaultLeaseTtl t2 @?= 52

    vaultUnmount conn "mymount"

    mounts3 <- vaultMounts conn
    lookup "mymount/" mounts3 @?= Nothing

    let pathBig = mkVaultSecretPath "big"
    vaultWrite conn pathBig (object ["A" .= 'a', "B" .= 'b'])

    (_, r) <- vaultRead conn pathBig
    case r of
        Left err -> assertFailure $ "Failed to parse secret/big: " ++ (show err)
        Right x -> vsvData x @?= object ["A" .= 'a', "B" .= 'b']

    let pathFun = mkVaultSecretPath "fun"
    vaultWrite conn pathFun (FunStuff "fun" [1, 2, 3])
    (_, r2) <- vaultRead conn pathFun
    case r2 of
        Left err -> assertFailure $ "Failed to parse secret/fun: " ++ (show err)
        Right x -> vsvData x @?= (FunStuff "fun" [1, 2, 3])

    (_, r3) <- vaultRead conn pathBig
    case r3 of
        Left (v, _) -> vsvData <$> fromJSON v @?= Success (object ["A" .= 'a', "B" .= 'b'])
        Right (x :: VaultSecretVersion FunStuff) -> assertFailure $ "Somehow parsed an impossible value" ++ show x

    let pathFooBarA = mkVaultSecretPath "foo/bar/a"
        pathFooBarB = mkVaultSecretPath "foo/bar/b"
        pathFooBarABCDEFG = mkVaultSecretPath "foo/bar/a/b/c/d/e/f/g"
        pathFooQuackDuck = mkVaultSecretPath "foo/quack/duck"

    vaultWrite conn pathFooBarA (object ["X" .= 'x'])
    vaultWrite conn pathFooBarB (object ["X" .= 'x'])
    vaultWrite conn pathFooBarABCDEFG (object ["X" .= 'x'])
    vaultWrite conn pathFooQuackDuck (object ["X" .= 'x'])

    let emptySecretPath = mkVaultSecretPath ""
    keys <- vaultList conn emptySecretPath
    assertBool "Secret in list" $ pathBig `elem` keys
    vaultDelete conn pathBig

    keys2 <- vaultList conn emptySecretPath
    assertBool "Secret not in list" $ not (pathBig `elem` keys2)

    keys3 <- vaultListRecursive conn (mkVaultSecretPath "foo")
    sort keys3
        @?= sort
            [ pathFooBarA
            , pathFooBarB
            , pathFooBarABCDEFG
            , pathFooQuackDuck
            ]

    vaultAuthEnable conn "approle"

    let pathSmall = mkVaultSecretPath "small"
    vaultWrite conn pathSmall (object ["X" .= 'x'])

    vaultPolicyCreate conn "foo" "path \"secret/small\" { capabilities = [\"read\"] }"

    vaultAppRoleCreate conn "foo-role" defaultVaultAppRoleParameters{_VaultAppRoleParameters_Policies = ["foo"]}

    roleId <- vaultAppRoleRoleIdRead conn "foo-role"
    secretId <- _VaultAppRoleSecretIdGenerateResponse_SecretId <$> vaultAppRoleSecretIdGenerate conn "foo-role" ""

    arConn <- connectToVaultAppRole addr roleId secretId
    (_, ar1) <- vaultRead conn pathSmall
    case ar1 of
        Left (v, _) -> vsvData <$> fromJSON v @?= Success (object ["X" .= 'x'])
        Right (x :: VaultSecretVersion FunStuff) -> assertFailure $ "Somehow parsed an impossible value" ++ show x

    vaultSeal conn

    status5 <- vaultSealStatus addr
    status5
        @?= VaultSealStatus
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

mkVaultSecretPath :: Text -> VaultSecretPath
mkVaultSecretPath searchPath = VaultSecretPath (VaultMountedPath "secret", VaultSearchPath searchPath)
