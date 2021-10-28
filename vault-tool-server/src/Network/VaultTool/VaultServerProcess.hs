{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.VaultTool.VaultServerProcess (
    VaultServerProcess,
    launchVaultServerProcess,
    shutdownVaultServerProcess,
    withVaultServerProcess,
    VaultBackendConfig,
    withVaultConfigFile,
    vaultConfigDefaultAddress,
    vaultAddress,
    readVaultBackendConfig,
    readVaultUnsealKeys,
) where

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async
import Control.Exception (Exception, Handler (Handler), IOException, bracket, bracketOnError, catches, throwIO, try)
import Control.Monad (forever)
import Data.Aeson
import qualified Data.ByteString.Lazy as BL
import Data.Functor ((<&>))
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import Network.HTTP.Client (HttpException)
import System.Exit (ExitCode)
import System.FilePath ((</>))
import System.IO (Handle, hClose)
import System.IO.Temp
import System.Process

import Network.VaultTool

{- | The ""backend"" section of the Vault server configuration.

 See <https://www.vaultproject.io/docs/config/index.html>

 > {
 >   "consul": {
 >     "address": "127.0.0.1:8500",
 >     "path": "vault"
 >   }
 > }

 > {
 >   "file": {
 >     "path": "vault-storage"
 >   }
 > }
-}
type VaultBackendConfig = Value

data VaultConfig = VaultConfig
    { _VaultConfig_Backend :: VaultBackendConfig
    , _VaultConfig_ListenAddress :: Text
    }
    deriving (Show)

instance ToJSON VaultConfig where
    toJSON VaultConfig{..} =
        object
            [ "backend" .= _VaultConfig_Backend
            , "listener"
                .= object
                    [ "tcp"
                        .= object
                            [ "tls_disable" .= T.pack "true"
                            , "address" .= _VaultConfig_ListenAddress
                            ]
                    ]
            , "disable_mlock" .= True
            ]

vaultConfigDefaultAddress :: VaultBackendConfig -> VaultConfig
vaultConfigDefaultAddress b =
    VaultConfig
        { _VaultConfig_Backend = b
        , _VaultConfig_ListenAddress = defaultAddress
        }
  where
    defaultAddress = "127.0.0.1:8200"

{- | Get the address that can be used to connect to a running Vault server
 launched with the specified config.

 The returned value will begin with ""http://"" or ""https://"" (depending on
 the config)
-}
vaultAddress :: VaultConfig -> VaultAddress
vaultAddress VaultConfig{_VaultConfig_ListenAddress} =
    VaultAddress ("http://" `T.append` _VaultConfig_ListenAddress)

readVaultBackendConfig :: FilePath -> IO VaultBackendConfig
readVaultBackendConfig file = do
    fileContents <- BL.readFile file
    case eitherDecode' fileContents of
        Left err -> error $ "Error loading file " ++ show file ++ ": " ++ err
        Right v -> pure v

-- | File should have one line per key (blank lines are ignored)
readVaultUnsealKeys :: FilePath -> IO [VaultUnsealKey]
readVaultUnsealKeys file =
    T.readFile file <&> (map VaultUnsealKey . filter (not . T.null) . map T.strip . T.lines)

withVaultConfigFile :: VaultConfig -> (FilePath -> IO a) -> IO a
withVaultConfigFile vaultConfig action = do
    withSystemTempDirectory "hs_vault" $ \tmpDir -> do
        let configFile = tmpDir </> "vault.cfg"
        BL.writeFile configFile (encode vaultConfig)
        action configFile

data VaultServerProcess = VaultServerProcess
    { vs_processHandle :: ProcessHandle
    , vs_stdinH :: Handle
    , vs_stdoutH :: Handle
    , vs_stderrH :: Handle
    }

data VaultServerLaunchException
    = VaultServerLaunchException_VaultStartTimeout
    | VaultServerLaunchException_ConnectTimeout
    | VaultServerLaunchException_ExecFailure IOException
    | VaultServerLaunchException_ProcessFailure ExitCode Text
    deriving (Show, Eq)

instance Exception VaultServerLaunchException

withVaultServerProcess :: Maybe FilePath -> FilePath -> VaultAddress -> IO a -> IO a
withVaultServerProcess mbVaultExe vaultConfigFile addr act = do
    bracket
        (launchVaultServerProcess mbVaultExe vaultConfigFile addr)
        shutdownVaultServerProcess
        (const act)

launchVaultServerProcess :: Maybe FilePath -> FilePath -> VaultAddress -> IO VaultServerProcess
launchVaultServerProcess mbVaultExe vaultConfigFile addr = do
    bracketOnError
        (execProcess vaultExe vaultConfigFile)
        shutdownVaultServerProcess
        $ \vs -> do
            withAsync (waitUntilRunningThread (vs_stdoutH vs)) $ \waitUntilRunningA -> do
                withAsync (checkProcessFailureThread vs) $ \startupErrorA -> do
                    _ <- waitAnyCancel [waitUntilRunningA, startupErrorA]
                    pure vs
  where
    vaultExe = fromMaybe "vault" mbVaultExe
    waitUntilRunningThread stdoutH = do
        withAsync (waitUntilVaultStarted stdoutH) $ \startA -> do
            withAsync (timeout vaultStartTimeoutMilliseconds VaultServerLaunchException_VaultStartTimeout) $ \timeoutA -> do
                _ <- waitAnyCancel [startA, timeoutA]
                pure ()
        withAsync waitUntilVaultConnect $ \connectA -> do
            withAsync (timeout vaultConnectTimeoutMilliseconds VaultServerLaunchException_ConnectTimeout) $ \timeoutA -> do
                _ <- waitAnyCancel [connectA, timeoutA]
                pure ()
    checkProcessFailureThread vs = do
        mbExitCode <- getProcessExitCode (vs_processHandle vs)
        case mbExitCode of
            Just exitCode -> do
                stderrText <- T.hGetContents (vs_stderrH vs)
                throwIO $ VaultServerLaunchException_ProcessFailure exitCode stderrText
            Nothing -> do
                threadDelay (checkExitedSnoozeMilliseconds * 1000)
                checkProcessFailureThread vs
    vaultStartTimeoutMilliseconds = 10000
    vaultConnectTimeoutMilliseconds = 10000
    checkRunningSnoozeMilliseconds = 10
    checkExitedSnoozeMilliseconds = 10
    timeout milliseconds ex = do
        threadDelay (milliseconds * 1000)
        throwIO ex
    waitUntilVaultStarted stdoutH = do
        tryResult <- try $ T.hGetLine stdoutH
        case tryResult of
            Left (_ :: IOException) ->
                -- Wait to be killed
                forever (threadDelay 100000000)
            Right ln -> do
                -- This expects the vault program to output the string below to stdout. Verified to work for Vault versions [0.1.0 .. 0.6.0]
                if vaultStartMessagePrefix `T.isPrefixOf` ln
                    then pure ()
                    else waitUntilVaultStarted stdoutH
    vaultStartMessagePrefix = "==> Vault server started!"
    waitUntilVaultConnect = do
        running <- vaultIsRunning addr
        if running
            then pure ()
            else do
                threadDelay (checkRunningSnoozeMilliseconds * 1000)
                waitUntilVaultConnect

execProcess :: FilePath -> FilePath -> IO VaultServerProcess
execProcess vaultExe vaultConfigFile = do
    tryResult <-
        try $
            createProcess $
                (proc vaultExe ["server", "-config=" ++ vaultConfigFile])
                    { env = Just []
                    , std_in = CreatePipe
                    , std_out = CreatePipe
                    , std_err = CreatePipe
                    , close_fds = True
                    }
    case tryResult of
        Left ex -> throwIO $ VaultServerLaunchException_ExecFailure ex
        Right (Just stdinH, Just stdoutH, Just stderrH, processHandle) ->
            pure
                VaultServerProcess
                    { vs_processHandle = processHandle
                    , vs_stdinH = stdinH
                    , vs_stdoutH = stdoutH
                    , vs_stderrH = stderrH
                    }
        Right _ -> error "execProcess: The Impossible Happened"

shutdownVaultServerProcess :: VaultServerProcess -> IO ()
shutdownVaultServerProcess vs = do
    -- TODO Should send SIGINT instead
    terminateProcess (vs_processHandle vs)
    _ <- waitForProcess (vs_processHandle vs)
    hClose (vs_stdinH vs)
    hClose (vs_stdoutH vs)
    hClose (vs_stderrH vs)

vaultIsRunning :: VaultAddress -> IO Bool
vaultIsRunning addr = do
    (vaultHealth addr >> pure True)
        `catches` [ Handler $ \(_ :: HttpException) -> pure False
                  , Handler $ \(_ :: VaultException) -> pure False
                  ]
