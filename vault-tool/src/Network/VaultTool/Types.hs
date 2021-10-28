{-# LANGUAGE OverloadedStrings #-}

module Network.VaultTool.Types (
    VaultAddress (..),
    VaultAppRoleId (..),
    VaultAppRoleSecretId (..),
    VaultAppRoleSecretIdAccessor (..),
    VaultAuthToken (..),
    VaultConnection,
    VaultException (..),
    VaultMountedPath (..),
    VaultSearchPath (..),
    VaultSecretPath (..),
    VaultUnsealKey (..),
    mkAuthenticatedVaultConnection,
    mkUnauthenticatedVaultConnection,
    vaultAddress,
    vaultAuthToken,
    vaultConnectionManager,
) where

import Control.Exception (Exception)
import Data.Aeson
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import Network.HTTP.Client (Manager)

data VaultConnection
    = AuthenticatedVaultConnection VaultAddress Manager VaultAuthToken
    | UnauthenticatedVaultConnection VaultAddress Manager

mkAuthenticatedVaultConnection :: VaultAddress -> Manager -> VaultAuthToken -> VaultConnection
mkAuthenticatedVaultConnection = AuthenticatedVaultConnection

mkUnauthenticatedVaultConnection :: VaultAddress -> Manager -> VaultConnection
mkUnauthenticatedVaultConnection = UnauthenticatedVaultConnection

vaultAddress :: VaultConnection -> VaultAddress
vaultAddress (AuthenticatedVaultConnection addr _ _) = addr
vaultAddress (UnauthenticatedVaultConnection addr _) = addr

vaultConnectionManager :: VaultConnection -> Manager
vaultConnectionManager (AuthenticatedVaultConnection _ mgr _) = mgr
vaultConnectionManager (UnauthenticatedVaultConnection _ mgr) = mgr

vaultAuthToken :: VaultConnection -> Maybe VaultAuthToken
vaultAuthToken (AuthenticatedVaultConnection _ _ token) = Just token
vaultAuthToken (UnauthenticatedVaultConnection _ _) = Nothing

newtype VaultAddress = VaultAddress {unVaultAddress :: Text}
    deriving (Show, Eq, Ord)

newtype VaultUnsealKey = VaultUnsealKey {unVaultUnsealKey :: Text}
    deriving (Show, Eq, Ord)

newtype VaultAuthToken = VaultAuthToken {unVaultAuthToken :: Text}
    deriving (Show, Eq, Ord)

instance FromJSON VaultAuthToken where
    parseJSON j = do
        text <- parseJSON j
        pure (VaultAuthToken text)

newtype VaultMountedPath = VaultMountedPath {unVaultMountedPath :: Text}
    deriving (Show, Eq, Ord)

newtype VaultSearchPath = VaultSearchPath {unVaultSearchPath :: Text}
    deriving (Show, Eq, Ord)

newtype VaultSecretPath = VaultSecretPath (VaultMountedPath, VaultSearchPath)
    deriving (Show, Eq, Ord)

newtype VaultAppRoleId = VaultAppRoleId {unVaultAppRoleId :: Text}
    deriving (Show, Eq, Ord)

instance FromJSON VaultAppRoleId where
    parseJSON (Object v) = VaultAppRoleId <$> v .: "role_id"
    parseJSON _ = fail "Not an Object"

instance ToJSON VaultAppRoleId where
    toJSON v = object ["role_id" .= unVaultAppRoleId v]

newtype VaultAppRoleSecretId = VaultAppRoleSecretId {unVaultAppRoleSecretId :: Text}
    deriving (Show, Eq, Ord)

instance FromJSON VaultAppRoleSecretId where
    parseJSON j = do
        text <- parseJSON j
        pure $ VaultAppRoleSecretId text

instance ToJSON VaultAppRoleSecretId where
    toJSON v = object ["secret_id" .= unVaultAppRoleSecretId v]

newtype VaultAppRoleSecretIdAccessor = VaultAppRoleSecretIdAccessor {unVaultAppRoleSecretIdAccessor :: Text}
    deriving (Show, Eq, Ord)

instance FromJSON VaultAppRoleSecretIdAccessor where
    parseJSON j = do
        text <- parseJSON j
        pure $ VaultAppRoleSecretIdAccessor text

instance ToJSON VaultAppRoleSecretIdAccessor where
    toJSON v = object ["secret_id_accessor" .= unVaultAppRoleSecretIdAccessor v]

data VaultException
    = VaultException
    | VaultException_InvalidAddress ByteString Text
    | VaultException_BadStatusCode ByteString Text BL.ByteString Int BL.ByteString
    | VaultException_ParseBodyError ByteString Text BL.ByteString Text
    deriving (Show, Eq)

instance Exception VaultException
