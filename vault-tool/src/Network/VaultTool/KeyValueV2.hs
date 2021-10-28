{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

{- | A library for working with Vault's KeyValue version 2 secrets engine

 Unless otherwise specified, all IO functions in this module may
 potentially throw 'HttpException' or 'VaultException'
-}
module Network.VaultTool.KeyValueV2 (
    VaultSecretVersion (..),
    VaultSecretVersionMetadata (..),
    VaultSecretMetadata (..),
    vaultWrite,
    vaultRead,
    vaultReadVersion,
    vaultDelete,
    vaultList,
    isFolder,
    vaultListRecursive,
) where

import Control.Applicative ((<|>))
import Control.Exception (throwIO)
import Data.Aeson (
    FromJSON,
    ToJSON,
    Value (..),
    encode,
    object,
    parseJSON,
    toJSON,
    withObject,
    (.:),
    (.=),
 )
import Data.Aeson.Types (parseEither)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime)

import Network.VaultTool.Internal (
    newDeleteRequest,
    newGetRequest,
    newListRequest,
    newPostRequest,
    runVaultRequest,
    runVaultRequest_,
    withStatusCodes,
 )
import Network.VaultTool.Types (
    VaultConnection,
    VaultException (..),
    VaultMountedPath (..),
    VaultSearchPath (..),
    VaultSecretPath (..),
 )

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

data VaultSecretVersion a = VaultSecretVersion
    { vsvData :: a
    , vsvMetadata :: VaultSecretVersionMetadata
    }
    deriving (Show)

instance FromJSON a => FromJSON (VaultSecretVersion a) where
    parseJSON = withObject "VaultSecretVersion" $ \v ->
        VaultSecretVersion
            <$> v .: "data"
            <*> v .: "metadata"

data VaultSecretVersionMetadata = VaultSecretVersionMetadata
    { vsvmCreatedTime :: UTCTime
    , vsvmDeletionTime :: Maybe UTCTime
    , vsvmDestroyed :: Bool
    , vsvmVersion :: Int
    }
    deriving (Show)

instance FromJSON VaultSecretVersionMetadata where
    parseJSON = withObject "VaultSecretVersionMetadata" $ \v ->
        VaultSecretVersionMetadata
            <$> v .: "created_time"
            <*> (v .: "deletion_time" >>= parseOptionalDate)
            <*> v .: "destroyed"
            <*> v .: "version"
      where
        parseOptionalDate x = parseJSON x <|> pure Nothing

vaultRead ::
    FromJSON a =>
    VaultConnection ->
    VaultSecretPath ->
    -- | A 'Left' result
    -- means that the
    -- secret's "data"
    -- could not be
    -- parsed into the
    -- data structure
    -- that you
    -- requested.
    --
    -- You will get the
    -- "data" as a raw
    -- 'Value' as well as
    -- the error message
    -- from the parse
    -- failure
    IO (VaultSecretMetadata, Either (Value, String) (VaultSecretVersion a))
vaultRead conn path = vaultReadVersion conn path Nothing

vaultReadVersion ::
    FromJSON a =>
    VaultConnection ->
    VaultSecretPath ->
    Maybe Int ->
    -- | A 'Left' result
    -- means that the
    -- secret's "data"
    -- could not be
    -- parsed into the
    -- data structure
    -- that you
    -- requested.
    --
    -- You will get the
    -- "data" as a raw
    -- 'Value' as well as
    -- the error message
    -- from the parse
    -- failure
    IO (VaultSecretMetadata, Either (Value, String) (VaultSecretVersion a))
vaultReadVersion conn (VaultSecretPath (mountedPath, searchPath)) version = do
    let path = vaultActionPath ReadSecretVersion mountedPath searchPath <> queryParams
    rspObj <-
        runVaultRequest conn $
            newGetRequest path
    case parseEither parseJSON (Object rspObj) of
        Left err -> throwIO $ VaultException_ParseBodyError "GET" path (encode rspObj) (T.pack err)
        Right metadata -> case parseEither (.: "data") rspObj of
            Left err -> throwIO $ VaultException_ParseBodyError "GET" path (encode rspObj) (T.pack err)
            Right dataObj -> case parseEither parseJSON (Object dataObj) of
                Left err -> pure (metadata, Left (Object dataObj, err))
                Right data_ -> pure (metadata, Right data_)
  where
    queryParams = case version of
        Nothing -> ""
        Just n -> "?version=" <> T.pack (show n)

newtype DataWrapper a = DataWrapper a

instance ToJSON a => ToJSON (DataWrapper a) where
    toJSON (DataWrapper x) = object ["data" .= x]

{- | <https://www.vaultproject.io/docs/secrets/generic/index.html>

 The value that you give must encode as a JSON object
-}
vaultWrite :: ToJSON a => VaultConnection -> VaultSecretPath -> a -> IO ()
vaultWrite conn (VaultSecretPath (mountedPath, searchPath)) value = do
    let reqBody = value
    let path = vaultActionPath WriteSecret mountedPath searchPath
    _ <-
        runVaultRequest_ conn
            . withStatusCodes [200, 204]
            $ newPostRequest path (Just $ DataWrapper reqBody)
    pure ()

newtype VaultListResult = VaultListResult [Text]

instance FromJSON VaultListResult where
    parseJSON (Object v) = do
        data_ <- v .: "data"
        keys <- data_ .: "keys"
        pure (VaultListResult keys)
    parseJSON _ = fail "Not an Object"

{- | <https://www.vaultproject.io/docs/secrets/generic/index.html>

 This will normalise the results to be full secret paths.

 Will return only secrets that in the are located in the folder hierarchy
 directly below the given folder.

 Use 'isFolder' to check if whether each result is a secret or a subfolder.

 The order of the results is unspecified.

 To recursively retrieve all of the secrets use 'vaultListRecursive'
-}
vaultList :: VaultConnection -> VaultSecretPath -> IO [VaultSecretPath]
vaultList conn (VaultSecretPath (VaultMountedPath mountedPath, VaultSearchPath searchPath)) = do
    let path = vaultActionPath ListSecrets (VaultMountedPath mountedPath) (VaultSearchPath searchPath)
    VaultListResult keys <-
        runVaultRequest conn $
            newListRequest path
    pure $ map (VaultSecretPath . fullSecretPath) keys
  where
    fullSecretPath key = (VaultMountedPath mountedPath, VaultSearchPath (withTrailingSlash `T.append` key))
    withTrailingSlash
        | T.null searchPath = ""
        | T.last searchPath == '/' = searchPath
        | otherwise = searchPath `T.snoc` '/'

{- | Recursively calls 'vaultList' to retrieve all of the secrets in a folder
 (including all subfolders and sub-subfolders, etc...)

 There will be no folders in the result.

 The order of the results is unspecified.
-}
vaultListRecursive :: VaultConnection -> VaultSecretPath -> IO [VaultSecretPath]
vaultListRecursive conn location = do
    paths <- vaultList conn location
    flip concatMapM paths $ \path -> do
        if isFolder path
            then vaultListRecursive conn path
            else pure [path]
  where
    concatMapM f xs = fmap concat (mapM f xs)

{- | Does the path end with a '/' character?

 Meant to be used on the results of 'vaultList'
-}
isFolder :: VaultSecretPath -> Bool
isFolder (VaultSecretPath (_, VaultSearchPath searchPath))
    | T.null searchPath = False
    | otherwise = T.last searchPath == '/'

-- | <https://www.vaultproject.io/docs/secrets/generic/index.html>
vaultDelete :: VaultConnection -> VaultSecretPath -> IO ()
vaultDelete conn (VaultSecretPath (mountedPath, searchPath)) = do
    let path = vaultActionPath HardDeleteSecret mountedPath searchPath
    _ <-
        runVaultRequest_ conn
            . withStatusCodes [204]
            $ newDeleteRequest path
    pure ()

data VaultAction
    = WriteConfig
    | ReadConfig
    | ReadSecretVersion
    | WriteSecret
    | SoftDeleteLatestSecret
    | SoftDeleteSecretVersions
    | UndeleteSecretVersions
    | DestroySecretVersions
    | ListSecrets
    | ReadSecretMetadata
    | WriteSecreteMetadata
    | HardDeleteSecret

vaultActionPath :: VaultAction -> VaultMountedPath -> VaultSearchPath -> Text
vaultActionPath action (VaultMountedPath mountedPath) (VaultSearchPath searchPath) =
    T.intercalate "/" [mountedPath, actionPrefix action, searchPath]
  where
    actionPrefix = \case
        WriteConfig -> "config"
        ReadConfig -> "config"
        ReadSecretVersion -> "data"
        WriteSecret -> "data"
        SoftDeleteLatestSecret -> "data"
        SoftDeleteSecretVersions -> "delete"
        UndeleteSecretVersions -> "undelete"
        DestroySecretVersions -> "destroy"
        ListSecrets -> "metadata"
        ReadSecretMetadata -> "metadata"
        WriteSecreteMetadata -> "metadata"
        HardDeleteSecret -> "metadata"
