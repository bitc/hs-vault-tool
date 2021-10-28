{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

{- | Unless otherwise specified, all IO functions in this module may
 potentially throw 'HttpException' or 'VaultException'
-}
module Network.VaultTool (
    VaultAddress (..),
    VaultUnsealKey (..),
    VaultAuthToken (..),
    VaultAppRoleId (..),
    VaultAppRoleSecretId (..),
    VaultException (..),
    VaultHealth (..),
    vaultHealth,
    connectToVault,
    connectToVaultAppRole,
    vaultAuthEnable,
    vaultPolicyCreate,
    vaultInit,
    VaultSealStatus (..),
    vaultSealStatus,
    vaultSeal,
    VaultUnseal (..),
    vaultUnseal,
    vaultAppRoleCreate,
    vaultAppRoleRoleIdRead,
    vaultAppRoleSecretIdGenerate,
    defaultVaultAppRoleParameters,
    VaultAppRoleParameters (..),
    VaultAppRoleSecretIdGenerateResponse (..),
    VaultMount (..),
    VaultMountRead,
    VaultMountWrite,
    VaultMountConfig (..),
    VaultMountConfigRead,
    VaultMountConfigWrite,
    VaultMountOptions (..),
    VaultMountConfigOptions,
    vaultMounts,
    vaultMountTune,
    vaultMountSetTune,
    vaultNewMount,
    vaultUnmount,
    VaultMountedPath (..),
    VaultSearchPath (..),
    VaultSecretPath (..),
) where

import Control.Exception (throwIO)
import Data.Aeson
import Data.Aeson.Types (Pair, parseEither)
import qualified Data.HashMap.Strict as H
import Data.List (sortOn)
import Data.Maybe (catMaybes)
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Client (Manager, newManager)
import Network.HTTP.Client.TLS (tlsManagerSettings)

import Network.VaultTool.Internal
import Network.VaultTool.Types

{- | <https://www.vaultproject.io/docs/http/sys-health.html>

 See 'vaultHealth'
-}
data VaultHealth = VaultHealth
    { _VaultHealth_Version :: Text
    , _VaultHealth_ServerTimeUtc :: Int
    , _VaultHealth_Initialized :: Bool
    , _VaultHealth_Sealed :: Bool
    , _VaultHealth_Standby :: Bool
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultHealth where
    parseJSON (Object v) =
        VaultHealth
            <$> v .: "version"
            <*> v .: "server_time_utc"
            <*> v .: "initialized"
            <*> v .: "sealed"
            <*> v .: "standby"
    parseJSON _ = fail "Not an Object"

-- | https://www.vaultproject.io/docs/http/sys-health.html
vaultHealth :: VaultAddress -> IO VaultHealth
vaultHealth addr = do
    manager <- newManager tlsManagerSettings
    runVaultRequest (mkUnauthenticatedVaultConnection addr manager)
        . withStatusCodes expectedStatusCodes
        $ newGetRequest "/sys/health"
  where
    expectedStatusCodes = [200, 429, 501, 503]

{- | Just initializes the 'VaultConnection' objects, does not actually make any
 contact with the vault server. (That is also the explanation why there is no
 function to disconnect)
-}
connectToVault :: VaultAddress -> VaultAuthToken -> IO VaultConnection
connectToVault addr authToken = do
    manager <- newManager tlsManagerSettings
    pure $ mkAuthenticatedVaultConnection addr manager authToken

{- | Initializes the 'VaultConnection' objects using approle credentials to retrieve an authtoken,
 and then calls `connectToVault`
-}
connectToVaultAppRole :: VaultAddress -> VaultAppRoleId -> VaultAppRoleSecretId -> IO VaultConnection
connectToVaultAppRole addr roleId secretId = do
    manager <- newManager tlsManagerSettings
    authToken <- vaultAppRoleLogin addr manager roleId secretId
    connectToVault addr authToken

{- | <https://www.vaultproject.io/docs/http/sys-init.html>

 See 'vaultInit'
-}
data VaultInitResponse = VaultInitResponse
    { _VaultInitResponse_Keys :: [Text]
    , _VaultInitResponse_RootToken :: VaultAuthToken
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultInitResponse where
    parseJSON (Object v) =
        VaultInitResponse
            <$> v .: "keys"
            <*> v .: "root_token"
    parseJSON _ = fail "Not an Object"

-- | <https://www.vaultproject.io/docs/http/sys-init.html>
vaultInit ::
    VaultAddress ->
    -- | @secret_shares@: The number of shares to split the master key
    -- into
    Int ->
    -- | @secret_threshold@: The number of shares required to
    -- reconstruct the master key. This must be less than or equal to
    -- secret_shares
    Int ->
    -- | master keys and initial root token
    IO ([VaultUnsealKey], VaultAuthToken)
vaultInit addr secretShares secretThreshold = do
    let reqBody =
            object
                [ "secret_shares" .= secretShares
                , "secret_threshold" .= secretThreshold
                ]
    manager <- newManager tlsManagerSettings
    rsp <-
        runVaultRequest (mkUnauthenticatedVaultConnection addr manager) $
            newPutRequest "/sys/init" (Just reqBody)
    let VaultInitResponse{_VaultInitResponse_Keys, _VaultInitResponse_RootToken} = rsp
    pure (map VaultUnsealKey _VaultInitResponse_Keys, _VaultInitResponse_RootToken)

{- | <https://www.vaultproject.io/docs/http/sys-seal-status.html>

 See 'vaultSealStatus'
-}
data VaultSealStatus = VaultSealStatus
    { _VaultSealStatus_Sealed :: Bool
    , -- | threshold
      _VaultSealStatus_T :: Int
    , -- | number of shares
      _VaultSealStatus_N :: Int
    , _VaultSealStatus_Progress :: Int
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultSealStatus where
    parseJSON (Object v) =
        VaultSealStatus
            <$> v .: "sealed"
            <*> v .: "t"
            <*> v .: "n"
            <*> v .: "progress"
    parseJSON _ = fail "Not an Object"

vaultSealStatus :: VaultAddress -> IO VaultSealStatus
vaultSealStatus addr = do
    manager <- newManager tlsManagerSettings
    runVaultRequest
        (mkUnauthenticatedVaultConnection addr manager)
        (newGetRequest "/sys/seal-status")

{- | <https://www.vaultproject.io/api/auth/approle/index.html>

 See 'sample-response-7'
-}
data VaultAuth = VaultAuth
    { _VaultAuth_Renewable :: Bool
    , _VaultAuth_LeaseDuration :: Int
    , _VaultAuth_Policies :: [Text]
    , _VaultAuth_ClientToken :: VaultAuthToken
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultAuth where
    parseJSON (Object v) =
        VaultAuth
            <$> v .: "renewable"
            <*> v .: "lease_duration"
            <*> v .: "policies"
            <*> v .: "client_token"
    parseJSON _ = fail "Not an Object"

{- | <https://www.vaultproject.io/api/auth/approle/index.html>

 See 'sample-response-7'
-}
data VaultAppRoleResponse = VaultAppRoleResponse
    { _VaultAppRoleResponse_Auth :: Maybe VaultAuth
    , _VaultAppRoleResponse_Warnings :: Value
    , _VaultAppRoleResponse_WrapInfo :: Value
    , _VaultAppRoleResponse_Data :: Value
    , _VaultAppRoleResponse_LeaseDuration :: Int
    , _VaultAppRoleResponse_Renewable :: Bool
    , _VaultAppRoleResponse_LeaseId :: Text
    }
    deriving (Show, Eq)

instance FromJSON VaultAppRoleResponse where
    parseJSON (Object v) =
        VaultAppRoleResponse
            <$> v .:? "auth"
            <*> v .: "warnings"
            <*> v .: "wrap_info"
            <*> v .: "data"
            <*> v .: "lease_duration"
            <*> v .: "renewable"
            <*> v .: "lease_id"
    parseJSON _ = fail "Not an Object"

-- | <https://www.vaultproject.io/docs/auth/approle.html>
vaultAppRoleLogin :: VaultAddress -> Manager -> VaultAppRoleId -> VaultAppRoleSecretId -> IO VaultAuthToken
vaultAppRoleLogin addr manager roleId secretId = do
    response <-
        runVaultRequest (mkUnauthenticatedVaultConnection addr manager) $
            newPostRequest "/auth/approle/login" (Just reqBody)
    maybe failOnNullAuth (return . _VaultAuth_ClientToken) $ _VaultAppRoleResponse_Auth response
  where
    reqBody =
        object
            [ "role_id" .= unVaultAppRoleId roleId
            , "secret_id" .= unVaultAppRoleSecretId secretId
            ]
    failOnNullAuth = fail "Auth on login is null"

-- | <https://www.vaultproject.io/docs/auth/approle.html#via-the-api-1>
vaultAuthEnable :: VaultConnection -> Text -> IO ()
vaultAuthEnable conn authMethod = do
    _ <-
        runVaultRequest_ conn
            . withStatusCodes [200, 204]
            $ newPostRequest ("/sys/auth/" <> authMethod) (Just reqBody)
    pure ()
  where
    reqBody = object ["type" .= authMethod]

-- | <https://www.vaultproject.io/api/system/policies.html#create-update-acl-policy>
vaultPolicyCreate :: VaultConnection -> Text -> Text -> IO ()
vaultPolicyCreate conn policyName policy = do
    _ <-
        runVaultRequest_ conn
            . withStatusCodes [200, 204]
            $ newPutRequest
                ("/sys/policies/acl/" <> policyName)
                (Just reqBody)
    pure ()
  where
    reqBody = object ["policy" .= policy]

newtype VaultAppRoleListResponse = VaultAppRoleListResponse
    {_VaultAppRoleListResponse_AppRoles :: [Text]}

instance FromJSON VaultAppRoleListResponse where
    parseJSON (Object v) =
        VaultAppRoleListResponse
            <$> v .: "keys"
    parseJSON _ = fail "Not an Object"

{- | <https://www.vaultproject.io/api/auth/approle/index.html#create-new-approle>

 Note: For TTL fields, only integer number seconds, i.e. 3600, are supported
-}
data VaultAppRoleParameters = VaultAppRoleParameters
    { _VaultAppRoleParameters_BindSecretId :: Bool
    , _VaultAppRoleParameters_Policies :: [Text]
    , _VaultAppRoleParameters_SecretIdNumUses :: Maybe Int
    , _VaultAppRoleParameters_SecretIdTTL :: Maybe Int
    , _VaultAppRoleParameters_TokenNumUses :: Maybe Int
    , _VaultAppRoleParameters_TokenTTL :: Maybe Int
    , _VaultAppRoleParameters_TokenMaxTTL :: Maybe Int
    , _VaultAppRoleParameters_Period :: Maybe Int
    }

instance ToJSON VaultAppRoleParameters where
    toJSON v =
        object $
            [ "bind_secret_id" .= _VaultAppRoleParameters_BindSecretId v
            , "policies" .= _VaultAppRoleParameters_Policies v
            ]
                <> catMaybes
                    [ "secret_id_num_uses" .=? _VaultAppRoleParameters_SecretIdNumUses v
                    , "secret_id_ttl" .=? _VaultAppRoleParameters_SecretIdTTL v
                    , "token_num_uses" .=? _VaultAppRoleParameters_TokenNumUses v
                    , "token_ttl" .=? _VaultAppRoleParameters_TokenTTL v
                    , "token_max_ttl" .=? _VaultAppRoleParameters_TokenMaxTTL v
                    , "period" .=? _VaultAppRoleParameters_Period v
                    ]
      where
        (.=?) :: ToJSON x => Text -> Maybe x -> Maybe Pair
        t .=? x = (t .=) <$> x

instance FromJSON VaultAppRoleParameters where
    parseJSON (Object v) =
        VaultAppRoleParameters
            <$> v .: "bind_secret_id"
            <*> v .: "policies"
            <*> v .:? "secret_id_num_uses"
            <*> v .:? "secret_id_ttl"
            <*> v .:? "token_num_uses"
            <*> v .:? "token_ttl"
            <*> v .:? "token_max_ttl"
            <*> v .:? "period"
    parseJSON _ = fail "Not an Object"

defaultVaultAppRoleParameters :: VaultAppRoleParameters
defaultVaultAppRoleParameters = VaultAppRoleParameters True [] Nothing Nothing Nothing Nothing Nothing Nothing

-- | <https://www.vaultproject.io/api/auth/approle/index.html#create-new-approle>
vaultAppRoleCreate :: VaultConnection -> Text -> VaultAppRoleParameters -> IO ()
vaultAppRoleCreate conn appRoleName varp = do
    _ <-
        runVaultRequest_ conn
            . withStatusCodes [200, 204]
            $ newPostRequest ("/auth/approle/role/" <> appRoleName) (Just varp)
    pure ()

-- | <https://www.vaultproject.io/api/auth/approle/index.html#read-approle-role-id>
vaultAppRoleRoleIdRead :: VaultConnection -> Text -> IO VaultAppRoleId
vaultAppRoleRoleIdRead conn appRoleName = do
    response <-
        runVaultRequest conn $
            newGetRequest ("/auth/approle/role/" <> appRoleName <> "/role-id")
    let d = _VaultAppRoleResponse_Data response
    case parseEither parseJSON d of
        Left err -> throwIO $ VaultException_ParseBodyError "GET" ("/auth/approle/role/" <> appRoleName <> "/role-id") (encode d) (T.pack err)
        Right obj -> return obj

data VaultAppRoleSecretIdGenerateResponse = VaultAppRoleSecretIdGenerateResponse
    { _VaultAppRoleSecretIdGenerateResponse_SecretIdAccessor :: VaultAppRoleSecretIdAccessor
    , _VaultAppRoleSecretIdGenerateResponse_SecretId :: VaultAppRoleSecretId
    }

instance FromJSON VaultAppRoleSecretIdGenerateResponse where
    parseJSON (Object v) =
        VaultAppRoleSecretIdGenerateResponse
            <$> v .: "secret_id_accessor"
            <*> v .: "secret_id"
    parseJSON _ = fail "Not an Object"

-- | <https://www.vaultproject.io/api/auth/approle/index.html#generate-new-secret-id>
vaultAppRoleSecretIdGenerate :: VaultConnection -> Text -> Text -> IO VaultAppRoleSecretIdGenerateResponse
vaultAppRoleSecretIdGenerate conn appRoleName metadata = do
    response <-
        runVaultRequest conn $
            newPostRequest ("/auth/approle/role/" <> appRoleName <> "/secret-id") (Just reqBody)
    let d = _VaultAppRoleResponse_Data response
    case parseEither parseJSON d of
        Left err -> throwIO $ VaultException_ParseBodyError "POST" ("/auth/approle/role/" <> appRoleName <> "/secret-id") (encode d) (T.pack err)
        Right obj -> return obj
  where
    reqBody = object ["metadata" .= metadata]

vaultSeal :: VaultConnection -> IO ()
vaultSeal conn = do
    _ <-
        runVaultRequest_ conn
            . withStatusCodes [200, 204]
            $ newPutRequest "/sys/seal" (Nothing :: Maybe ())
    pure ()

{- | <https://www.vaultproject.io/docs/http/sys-unseal.html>

 See 'vaultUnseal'
-}
data VaultUnseal
    = VaultUnseal_Key VaultUnsealKey
    | VaultUnseal_Reset
    deriving (Show, Eq, Ord)

-- | <https://www.vaultproject.io/docs/http/sys-unseal.html>
vaultUnseal :: VaultAddress -> VaultUnseal -> IO VaultSealStatus
vaultUnseal addr unseal = do
    let reqBody = case unseal of
            VaultUnseal_Key (VaultUnsealKey key) ->
                object
                    [ "key" .= key
                    ]
            VaultUnseal_Reset ->
                object
                    [ "reset" .= True
                    ]
    manager <- newManager tlsManagerSettings
    runVaultRequest (mkUnauthenticatedVaultConnection addr manager) $
        newPutRequest "/sys/unseal" (Just reqBody)

type VaultMountRead = VaultMount Text VaultMountConfigRead (Maybe VaultMountConfigOptions)
type VaultMountWrite = VaultMount (Maybe Text) (Maybe VaultMountConfigWrite) (Maybe VaultMountConfigOptions)
type VaultMountConfigRead = VaultMountConfig Int
type VaultMountConfigWrite = VaultMountConfig (Maybe Int)
type VaultMountConfigOptions = VaultMountOptions (Maybe Int)

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
data VaultMount a b c = VaultMount
    { _VaultMount_Type :: Text
    , _VaultMount_Description :: a
    , _VaultMount_Config :: b
    , _VaultMount_Options :: c
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultMountRead where
    parseJSON (Object v) =
        VaultMount
            <$> v .: "type"
            <*> v .: "description"
            <*> v .: "config"
            <*> v .: "options"
    parseJSON _ = fail "Not an Object"

instance ToJSON VaultMountWrite where
    toJSON v =
        object
            [ "type" .= _VaultMount_Type v
            , "description" .= _VaultMount_Description v
            , "config" .= _VaultMount_Config v
            , "options" .= _VaultMount_Options v
            ]

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
data VaultMountConfig a = VaultMountConfig
    { _VaultMountConfig_DefaultLeaseTtl :: a
    , _VaultMountConfig_MaxLeaseTtl :: a
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultMountConfigRead where
    parseJSON (Object v) =
        VaultMountConfig
            <$> v .: "default_lease_ttl"
            <*> v .: "max_lease_ttl"
    parseJSON _ = fail "Not an Object"

instance ToJSON VaultMountConfigWrite where
    toJSON v =
        object
            [ "default_lease_ttl" .= fmap formatSeconds (_VaultMountConfig_DefaultLeaseTtl v)
            , "max_lease_ttl" .= fmap formatSeconds (_VaultMountConfig_MaxLeaseTtl v)
            ]
      where
        formatSeconds :: Int -> String
        formatSeconds n = show n ++ "s"

newtype VaultMountOptions a = VaultMountOptions
    { _VaultMountOptions_Version :: a
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultMountConfigOptions where
    parseJSON (Object v) =
        VaultMountOptions
            <$> (read <$> v .: "version")
    parseJSON _ = fail "Not an Object"

instance ToJSON VaultMountConfigOptions where
    toJSON v =
        object
            [ "version" .= (show <$> _VaultMountOptions_Version v)
            ]

{- | <https://www.vaultproject.io/docs/http/sys-mounts.html>

 For your convenience, the results are returned sorted (by the mount point)
-}
vaultMounts :: VaultConnection -> IO [(Text, VaultMountRead)]
vaultMounts conn = do
    let reqPath = "/sys/mounts"
    rspObj <- runVaultRequest conn $ newGetRequest reqPath

    -- Vault 0.6.1 has a different format than previous versions.
    -- See <https://github.com/hashicorp/vault/issues/1965>
    --
    -- We do some detection to support both the new and the old format:
    let root = case H.lookup "data" rspObj of
            Nothing -> Object rspObj
            Just v -> v

    case parseEither parseJSON root of
        Left err -> throwIO $ VaultException_ParseBodyError "GET" reqPath (encode rspObj) (T.pack err)
        Right obj -> pure $ sortOn fst (H.toList obj)

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
vaultMountTune :: VaultConnection -> Text -> IO VaultMountConfigRead
vaultMountTune conn mountPoint =
    runVaultRequest conn
        . newGetRequest
        $ "/sys/mounts/" <> mountPoint <> "/tune"

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
vaultMountSetTune :: VaultConnection -> Text -> VaultMountConfigWrite -> IO ()
vaultMountSetTune conn mountPoint mountConfig = do
    let reqBody = mountConfig
    _ <-
        runVaultRequest_ conn
            . withStatusCodes [200, 204]
            $ newPostRequest ("/sys/mounts/" <> mountPoint <> "/tune") (Just reqBody)
    pure ()

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
vaultNewMount :: VaultConnection -> Text -> VaultMountWrite -> IO ()
vaultNewMount conn mountPoint vaultMount = do
    let reqBody = vaultMount
    _ <-
        runVaultRequest_ conn
            . withStatusCodes [200, 204]
            $ newPostRequest ("/sys/mounts/" <> mountPoint) (Just reqBody)
    pure ()

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
vaultUnmount :: VaultConnection -> Text -> IO ()
vaultUnmount conn mountPoint = do
    _ <-
        runVaultRequest_ conn
            . withStatusCodes [200, 204]
            . newDeleteRequest
            $ "/sys/mounts/" <> mountPoint
    pure ()

data VaultSecretMetadata = VaultSecretMetadata
    { _VaultSecretMetadata_leaseDuration :: Int
    , _VaultSecretMetadata_leaseId :: Text
    , _VauleSecretMetadata_renewable :: Bool
    }
    deriving (Show, Eq {- TODO Ord -})

instance FromJSON VaultSecretMetadata where
    parseJSON (Object v) =
        VaultSecretMetadata
            <$> v .: "lease_duration"
            <*> v .: "lease_id"
            <*> v .: "renewable"
    parseJSON _ = fail "Not an Object"
