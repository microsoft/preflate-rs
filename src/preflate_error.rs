/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

use std::fmt::Display;

#[allow(dead_code)]
#[derive(Debug)]
pub enum PreflateError {
    ReadDeflate(anyhow::Error),
    InvalidPredictionData(anyhow::Error),
    AnalyzeFailed(anyhow::Error),
    RecompressFailed(anyhow::Error),
    Mismatch(anyhow::Error),
    ReadBlock(usize, anyhow::Error),
    PredictBlock(usize, anyhow::Error),
    PredictTree(usize, anyhow::Error),
    RecreateBlock(usize, anyhow::Error),
    RecreateTree(usize, anyhow::Error),
    EncodeBlock(usize, anyhow::Error),
    InvalidCompressedWrapper,
    ZstdError(std::io::Error),
}

impl Display for PreflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflateError::InvalidPredictionData(e) => write!(f, "InvalidPredictionData: {}", e),
            PreflateError::ReadDeflate(e) => write!(f, "ReadDeflate: {}", e),
            PreflateError::Mismatch(e) => write!(f, "Mismatch: {}", e),
            PreflateError::ReadBlock(i, e) => write!(f, "ReadBlock[{}]: {}", i, e),
            PreflateError::PredictBlock(i, e) => write!(f, "PredictBlock[{}]: {}", i, e),
            PreflateError::PredictTree(i, e) => write!(f, "PredictTree[{}]: {}", i, e),
            PreflateError::RecreateBlock(i, e) => write!(f, "RecreateBlock[{}]: {}", i, e),
            PreflateError::RecreateTree(i, e) => write!(f, "RecreateTree[{}]: {}", i, e),
            PreflateError::EncodeBlock(i, e) => write!(f, "EncodeBlock[{}]: {}", i, e),
            PreflateError::RecompressFailed(e) => write!(f, "RecompressFailed: {}", e),
            PreflateError::AnalyzeFailed(e) => write!(f, "AnalyzeFailed: {}", e),
            PreflateError::InvalidCompressedWrapper => write!(f, "InvalidCompressedWrapper"),
            PreflateError::ZstdError(e) => write!(f, "ZstdError: {}", e),
        }
    }
}

impl std::error::Error for PreflateError {}
