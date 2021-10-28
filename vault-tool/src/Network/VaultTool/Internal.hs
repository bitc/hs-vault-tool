{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.VaultTool.Internal (
    VaultRequest,
    runVaultRequest,
    runVaultRequest_,
    newGetRequest,
    newPostRequest,
    newPutRequest,
    newDeleteRequest,
    newListRequest,
    withStatusCodes,
) where

import Control.Exception (throwIO)
import Control.Monad (unless, void)
import Data.Aeson
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Network.HTTP.Client
import Network.HTTP.Types.Header
import Network.HTTP.Types.Method
import Network.HTTP.Types.Status

import Network.VaultTool.Types

data VaultRequest a = VaultRequest
    { vrMethod :: Method
    , vrPath :: Text
    , vrBody :: Maybe a
    , vrExpectedStatuses :: [Int]
    }

newRequest :: Method -> Text -> Maybe a -> VaultRequest a
newRequest method path mbBody =
    VaultRequest
        { vrMethod = method
        , vrPath = path
        , vrBody = mbBody
        , vrExpectedStatuses = [200]
        }

newGetRequest :: Text -> VaultRequest ()
newGetRequest path = newRequest "GET" path Nothing

newPostRequest :: Text -> Maybe a -> VaultRequest a
newPostRequest = newRequest "POST"

newPutRequest :: Text -> Maybe a -> VaultRequest a
newPutRequest = newRequest "PUT"

newDeleteRequest :: Text -> VaultRequest ()
newDeleteRequest path = newRequest "DELETE" path Nothing

newListRequest :: Text -> VaultRequest ()
newListRequest path = newRequest "LIST" path Nothing

withStatusCodes :: [Int] -> VaultRequest a -> VaultRequest a
withStatusCodes statusCodes req = req{vrExpectedStatuses = statusCodes}

authTokenHeader :: VaultConnection -> RequestHeaders
authTokenHeader = maybe mempty mkAuthTokenHeader . vaultAuthToken
  where
    mkAuthTokenHeader (VaultAuthToken token) = [("X-Vault-Token", T.encodeUtf8 token)]

vaultRequest :: ToJSON a => VaultConnection -> VaultRequest a -> IO BL.ByteString
vaultRequest conn VaultRequest{vrMethod, vrPath, vrBody, vrExpectedStatuses} = do
    initReq <- case parseRequest absolutePath of
        Nothing -> throwIO $ VaultException_InvalidAddress vrMethod vrPath
        Just initReq -> pure initReq
    let reqBody = maybe BL.empty encode vrBody
        req =
            initReq
                { method = vrMethod
                , requestBody = RequestBodyLBS reqBody
                , requestHeaders = requestHeaders initReq ++ authTokenHeader conn
                }
    rsp <- httpLbs req (vaultConnectionManager conn)
    let s = statusCode (responseStatus rsp)
    unless (s `elem` vrExpectedStatuses) $ do
        throwIO $ VaultException_BadStatusCode vrMethod vrPath reqBody s (responseBody rsp)
    pure (responseBody rsp)
  where
    absolutePath = T.unpack $ T.intercalate "/" [unVaultAddress (vaultAddress conn), "v1", vrPath]

runVaultRequest :: (FromJSON b, ToJSON a) => VaultConnection -> VaultRequest a -> IO b
runVaultRequest conn req@VaultRequest{vrMethod, vrPath} = do
    rspBody <- vaultRequest conn req
    case eitherDecode' rspBody of
        Left err -> throwIO $ VaultException_ParseBodyError vrMethod vrPath rspBody (T.pack err)
        Right x -> pure x

runVaultRequest_ :: (ToJSON a) => VaultConnection -> VaultRequest a -> IO ()
runVaultRequest_ conn = void . vaultRequest conn
