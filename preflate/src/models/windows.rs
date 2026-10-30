/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use crate::hash_algorithm::HashAlgorithm;

// Windows DEFLATE uses fixed table-XOR hashing rather than zlib's rotating hash.
pub(crate) const HASH: HashAlgorithm = HashAlgorithm::RandomVector;
