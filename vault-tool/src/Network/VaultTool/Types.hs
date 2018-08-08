{-# LANGUAGE OverloadedStrings #-}

module Network.VaultTool.Types where

import Control.Exception (Exception)
import Data.Aeson
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.ByteString.Lazy as BL

newtype VaultAddress = VaultAddress { unVaultAddress :: Text }
    deriving (Show, Eq, Ord)

newtype VaultUnsealKey = VaultUnsealKey { unVaultUnsealKey :: Text }
    deriving (Show, Eq, Ord)

newtype VaultAuthToken = VaultAuthToken { unVaultAuthToken :: Text }
    deriving (Show, Eq, Ord)

instance FromJSON VaultAuthToken where
    parseJSON j = do
        text <- parseJSON j
        pure (VaultAuthToken text)

newtype VaultSecretPath = VaultSecretPath { unVaultSecretPath :: Text }
    deriving (Show, Eq, Ord)

newtype VaultAppRoleId = VaultAppRoleId { unVaultAppRoleId :: Text }
    deriving (Show, Eq, Ord)

instance FromJSON VaultAppRoleId where
    parseJSON (Object v) = VaultAppRoleId <$> v .: "role_id"
    parseJSON _ = fail "Not an Object"

instance ToJSON VaultAppRoleId where
    toJSON v = object [ "role_id" .= unVaultAppRoleId v ]

newtype VaultAppRoleSecretId = VaultAppRoleSecretId { unVaultAppRoleSecretId :: Text }
    deriving (Show, Eq, Ord)

instance FromJSON VaultAppRoleSecretId where
    parseJSON j = do
        text <- parseJSON j
        pure $ VaultAppRoleSecretId text

instance ToJSON VaultAppRoleSecretId where
    toJSON v = object [ "secret_id" .= unVaultAppRoleSecretId v ]

newtype VaultAppRoleSecretIdAccessor = VaultAppRoleSecretIdAccessor { unVaultAppRoleSecretIdAccessor :: Text }
    deriving (Show, Eq, Ord)

instance FromJSON VaultAppRoleSecretIdAccessor where
    parseJSON j = do
        text <- parseJSON j
        pure $ VaultAppRoleSecretIdAccessor text

instance ToJSON VaultAppRoleSecretIdAccessor where
    toJSON v = object [ "secret_id_accessor" .= unVaultAppRoleSecretIdAccessor v ]

data VaultException
    = VaultException
    | VaultException_InvalidAddress ByteString String
    | VaultException_BadStatusCode ByteString String BL.ByteString Int BL.ByteString
    | VaultException_ParseBodyError ByteString String BL.ByteString String
    deriving (Show, Eq)

instance Exception VaultException
