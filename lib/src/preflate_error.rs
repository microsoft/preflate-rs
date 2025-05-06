/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::fmt::Display;
use std::io::ErrorKind;
use std::num::TryFromIntError;

#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum ExitCode {
    /// Could not reconstruct the deflate stream. This usually means that the data is corrupt.
    RecompressFailed = 4,

    /// Rountrip check failed. This means that the data was not compressed properly.
    RoundtripMismatch = 5,

    /// The compression wrapper was not valid, which means we cannot decompress the data.
    InvalidCompressedWrapper = 12,

    /// Error from zstd compression library.
    ZstdError = 14,

    /// Unexpected end of stream. This is usually a sign that the data is corrupt.
    ShortRead = 16,

    /// Error from the IO layer, eg Reader or Writer.
    OsError = 17,

    /// Internal error in the library.
    GeneralFailure = 18,

    /// Invalid PNG IDat chunk.
    InvalidIDat = 19,

    /// The deflate data stream contains an invalid match.
    MatchNotFound = 20,

    /// The deflate data stream is invalid or corrupt and cannot be properly read
    /// or reconstructed.
    InvalidDeflate = 21,

    /// We couldn't find a reasonable candidate for the version of the
    /// deflate algorithm used to compress the data. No gain would be
    /// had from recompressing the data since the amount of correction
    /// data would be larger than the original data.
    NoCompressionCandidates = 22,

    /// API was called with invalid parameters. For example, data was
    /// passed in after indicting that the stream was finished.
    InvalidParameter = 23,

    /// panic in rust code
    AssertionFailure = 24,

    /// Non-zero padding found in deflate, which we currently don't handle
    NonZeroPadding = 25,

    /// Unable to predict the sequence of compression. Doesn't mean that
    /// the deflate content was invalid, but just that we don't handle
    /// some of the rare corner cases.
    PredictionFailure = 26,

    /// Plain text memory limit exceeded
    PlainTextLimit = 27,
}

impl Display for ExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ExitCode {
    /// Converts the error code into an integer for use as an error code when
    /// returning from a C API.
    pub fn as_integer_error_code(self) -> i32 {
        self as i32
    }
}

/// Since errors are rare and stop everything, we want them to be as lightweight as possible.
#[derive(Debug, Clone)]
struct PreflateErrorInternal {
    exit_code: ExitCode,
    message: String,
}

/// Standard error returned by Preflate library
#[derive(Clone)]
pub struct PreflateError {
    i: Box<PreflateErrorInternal>,
}

/// don't show internal indirrection in debug output
impl std::fmt::Debug for PreflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.i.fmt(f)
    }
}

pub type Result<T> = std::result::Result<T, PreflateError>;

impl Display for PreflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}: {1}", self.i.exit_code, self.i.message)
    }
}

impl PreflateError {
    pub fn new(exit_code: ExitCode, message: impl AsRef<str>) -> PreflateError {
        PreflateError {
            i: Box::new(PreflateErrorInternal {
                exit_code,
                message: message.as_ref().to_owned(),
            }),
        }
    }

    pub fn exit_code(&self) -> ExitCode {
        self.i.exit_code
    }

    pub fn message(&self) -> &str {
        &self.i.message
    }

    #[cold]
    #[inline(never)]
    #[track_caller]
    pub fn add_context(&mut self) {
        self.i
            .message
            .push_str(&format!("\n at {}", std::panic::Location::caller()));
    }
}

#[cold]
#[track_caller]
pub fn err_exit_code<T>(error_code: ExitCode, message: impl AsRef<str>) -> Result<T> {
    let mut e = PreflateError::new(error_code, message.as_ref());
    e.add_context();
    return Err(e);
}

pub trait AddContext<T> {
    #[track_caller]
    fn context(self) -> Result<T>;
    fn with_context<FN: Fn() -> String>(self, f: FN) -> Result<T>;
}

impl<T, E: Into<PreflateError>> AddContext<T> for core::result::Result<T, E> {
    #[track_caller]
    fn context(self) -> Result<T> {
        match self {
            Ok(x) => Ok(x),
            Err(e) => {
                let mut e = e.into();
                e.add_context();
                Err(e)
            }
        }
    }

    #[track_caller]
    fn with_context<FN: Fn() -> String>(self, f: FN) -> Result<T> {
        match self {
            Ok(x) => Ok(x),
            Err(e) => {
                let mut e = e.into();
                e.i.message.push_str(&f());
                e.add_context();
                Err(e)
            }
        }
    }
}

impl std::error::Error for PreflateError {}

fn get_io_error_exit_code(e: &std::io::Error) -> ExitCode {
    if e.kind() == ErrorKind::UnexpectedEof {
        ExitCode::ShortRead
    } else {
        ExitCode::OsError
    }
}

impl From<TryFromIntError> for PreflateError {
    #[track_caller]
    fn from(e: TryFromIntError) -> Self {
        let mut e = PreflateError::new(ExitCode::GeneralFailure, e.to_string().as_str());
        e.add_context();
        e
    }
}

/// translates std::io::Error into PreflateError
impl From<std::io::Error> for PreflateError {
    #[track_caller]
    fn from(e: std::io::Error) -> Self {
        match e.downcast::<PreflateError>() {
            Ok(le) => {
                return le;
            }
            Err(e) => {
                let mut e = PreflateError::new(get_io_error_exit_code(&e), e.to_string().as_str());
                e.add_context();
                e
            }
        }
    }
}

/// translates PreflateError into std::io::Error, which involves putting into a Box and using Other
impl From<PreflateError> for std::io::Error {
    fn from(e: PreflateError) -> Self {
        return std::io::Error::new(std::io::ErrorKind::Other, e);
    }
}

#[test]
fn test_error_translation() {
    // test wrapping inside an io error
    fn my_std_error() -> core::result::Result<(), std::io::Error> {
        Err(PreflateError::new(ExitCode::RecompressFailed, "test error").into())
    }

    let e: PreflateError = my_std_error().unwrap_err().into();
    assert_eq!(e.exit_code(), ExitCode::RecompressFailed);
    assert_eq!(e.message(), "test error");

    // an IO error should be translated into an OsError
    let e: PreflateError =
        std::io::Error::new(std::io::ErrorKind::NotFound, "file not found").into();
    assert_eq!(e.exit_code(), ExitCode::OsError);
}
