/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::{fmt::Display, io::ErrorKind};

use anyhow::Error;

#[derive(Debug, Clone)]
pub struct PreflateError {
    /// standard error code
    exit_code: ExitCode,

    /// diagnostic message including location. Content should not be relied on.
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
#[non_exhaustive]
pub enum ExitCode {
    ReadDeflate = 1,
    InvalidPredictionData = 2,
    AnalyzeFailed = 3,
    RecompressFailed = 4,
    RoundtripMismatch = 5,
    ReadBlock = 6,
    PredictBlock = 7,
    PredictTree = 8,
    RecreateBlock = 9,
    RecreateTree = 10,
    EncodeBlock = 11,
    InvalidCompressedWrapper = 12,
    ZstdError = 14,
    InvalidParameterHeader = 15,
    ShortRead = 16,
    OsError = 17,
    GeneralFailure = 18,
}

/// translates std::io::Error into LeptonError
impl From<std::io::Error> for PreflateError {
    #[track_caller]
    fn from(e: std::io::Error) -> Self {
        match e.downcast::<PreflateError>() {
            Ok(le) => {
                return le;
            }
            Err(e) => {
                let caller = std::panic::Location::caller();
                return PreflateError {
                    exit_code: get_io_error_exit_code(&e),
                    message: format!("error {} at {}", e.to_string(), caller.to_string()),
                };
            }
        }
    }
}

impl Display for ExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Display for PreflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}: {1}", self.exit_code, self.message)
    }
}

impl From<anyhow::Error> for PreflateError {
    fn from(mut error: anyhow::Error) -> Self {
        // first see if there is a LeptonError already inside
        match error.downcast::<PreflateError>() {
            Ok(le) => {
                return le;
            }
            Err(old_error) => {
                error = old_error;
            }
        }

        // capture the original error string before we lose it due
        // to downcasting to look for stashed LeptonErrors
        let original_string = error.to_string();

        // see if there is a LeptonError hiding inside an io error
        // which happens if we cross an API boundary that returns an std::io:Error
        // like Read or Write
        match error.downcast::<std::io::Error>() {
            Ok(ioe) => match ioe.downcast::<PreflateError>() {
                Ok(le) => {
                    return le;
                }
                Err(e) => {
                    return PreflateError {
                        exit_code: get_io_error_exit_code(&e),
                        message: format!("{} {}", e, original_string),
                    };
                }
            },
            Err(_) => {}
        }

        // don't know what we got, so treat it as a general failure
        return PreflateError {
            exit_code: ExitCode::GeneralFailure,
            message: original_string,
        };
    }
}

fn get_io_error_exit_code(e: &std::io::Error) -> ExitCode {
    if e.kind() == ErrorKind::UnexpectedEof {
        ExitCode::ShortRead
    } else {
        ExitCode::OsError
    }
}

impl PreflateError {
    pub fn new(exit_code: ExitCode, message: &str) -> PreflateError {
        PreflateError {
            exit_code,
            message: message.to_owned(),
        }
    }

    pub fn error_on_block(exit_code: ExitCode, block_number: usize, e: &Error) -> PreflateError {
        PreflateError {
            exit_code,
            message: format!("Error on block {}: {}", block_number, e),
        }
    }

    pub fn wrap(exit_code: ExitCode, e: &impl Display) -> PreflateError {
        PreflateError {
            exit_code,
            message: e.to_string(),
        }
    }

    pub fn wrap_anyhow(exit_code: ExitCode, e: &anyhow::Error) -> PreflateError {
        PreflateError {
            exit_code,
            message: e.to_string(),
        }
    }

    pub fn exit_code(&self) -> ExitCode {
        self.exit_code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// translates LeptonError into std::io::Error, which involves putting into a Box and using Other
impl From<PreflateError> for std::io::Error {
    fn from(e: PreflateError) -> Self {
        return std::io::Error::new(std::io::ErrorKind::Other, e);
    }
}

impl std::error::Error for PreflateError {}

#[test]
fn test_error_translation() {
    // test wrapping inside an io error
    fn my_std_error() -> Result<(), std::io::Error> {
        Err(PreflateError::new(ExitCode::ReadDeflate, "test error").into())
    }

    let e: PreflateError = my_std_error().unwrap_err().into();
    assert_eq!(e.exit_code, ExitCode::ReadDeflate);
    assert_eq!(e.message, "test error");

    // wrapping inside anyhow
    fn my_anyhow() -> Result<(), anyhow::Error> {
        Err(PreflateError::new(ExitCode::ReadDeflate, "test error").into())
    }

    let e: PreflateError = my_anyhow().unwrap_err().into();
    assert_eq!(e.exit_code, ExitCode::ReadDeflate);
    assert_eq!(e.message, "test error");

    // an IO error should be translated into an OsError
    let e: PreflateError =
        std::io::Error::new(std::io::ErrorKind::NotFound, "file not found").into();
    assert_eq!(e.exit_code, ExitCode::OsError);
}
