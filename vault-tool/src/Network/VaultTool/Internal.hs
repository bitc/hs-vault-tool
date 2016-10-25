module Network.VaultTool.Internal where

import Control.Exception (throwIO)
import Control.Monad (when)
import Data.Aeson
import Network.HTTP.Client
import Network.HTTP.Types.Header
import Network.HTTP.Types.Method
import Network.HTTP.Types.Status
import qualified Data.ByteString.Lazy as BL

import Network.VaultTool.Types

vaultRequest :: ToJSON a => Manager -> Method -> String -> RequestHeaders -> Maybe a -> [Int] -> IO BL.ByteString
vaultRequest manager method_ path_ headers mbBody expectedStatus = do
    initReq <- case parseRequest path_ of
        Nothing -> throwIO $ VaultException_InvalidAddress method_ path_
        Just initReq -> pure initReq
    let reqBody = case mbBody of
            Nothing -> BL.empty
            Just b -> encode b
        req = initReq
            { method = method_
            , requestBody = RequestBodyLBS reqBody
            , requestHeaders = requestHeaders initReq ++ headers
            }
    rsp <- httpLbs req manager
    let s = statusCode (responseStatus rsp)
    when (not (elem s expectedStatus)) $ do
        throwIO $ VaultException_BadStatusCode method_ path_ reqBody s (responseBody rsp)
    pure (responseBody rsp)

vaultRequestJSON :: (FromJSON b, ToJSON a) => Manager -> Method -> String -> RequestHeaders -> Maybe a -> [Int] -> IO b
vaultRequestJSON manager method_ path_ headers mbBody expectedStatus = do
    rspBody <- vaultRequest manager method_ path_ headers mbBody expectedStatus
    case eitherDecode' rspBody of
        Left err -> throwIO $ VaultException_ParseBodyError method_ path_ rspBody err
        Right x -> pure x
