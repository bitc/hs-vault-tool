module Network.VaultTool.Types where

import Control.Exception (Exception)
import Data.Aeson
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Encoding as T

newtype VaultAddress = VaultAddress { unVaultAddress :: Text }
    deriving (Show, Eq, Ord)

newtype VaultUnsealKey = VaultUnsealKey { unVaultUnsealKey :: Text }
    deriving (Show, Eq, Ord)

newtype VaultAuthToken = VaultAuthToken { unVaultAuthToken :: ByteString }
    deriving (Show, Eq, Ord)

instance FromJSON VaultAuthToken where
    parseJSON j = do
        text <- parseJSON j
        pure (VaultAuthToken (T.encodeUtf8 text))

newtype VaultSecretPath = VaultSecretPath { unVaultSecretPath :: Text }
    deriving (Show, Eq, Ord)

data VaultException
    = VaultException
    | VaultException_InvalidAddress ByteString String
    | VaultException_BadStatusCode ByteString String BL.ByteString Int BL.ByteString
    | VaultException_ParseBodyError ByteString String BL.ByteString String
    deriving (Show, Eq)

instance Exception VaultException
