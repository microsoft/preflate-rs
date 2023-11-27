/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the Apache License, Version 2.0. See LICENSE.txt in the project root for license information.
 *  This software incorporates material from third parties. See NOTICE.txt for details.
 *--------------------------------------------------------------------------------------------*/

pub struct PreflateParserConfig {
    pub good_length: u32,
    pub max_lazy: u32,
    pub nice_length: u32,
    pub max_chain: u32,
}

pub const FAST_PREFLATE_PARSER_SETTINGS: [PreflateParserConfig; 3] = [
    // these three levels are used by zlib

    // max speed, no lazy matches (the lazy field means
    // the maximum length that is added to the dictionary during
    // a match)
    PreflateParserConfig {
        good_length: 4,
        max_lazy: 4,
        nice_length: 8,
        max_chain: 4,
    },
    PreflateParserConfig {
        good_length: 4,
        max_lazy: 5,
        nice_length: 16,
        max_chain: 8,
    },
    PreflateParserConfig {
        good_length: 4,
        max_lazy: 6,
        nice_length: 32,
        max_chain: 32,
    },
];

pub const SLOW_PREFLATE_PARSER_SETTINGS: [PreflateParserConfig; 6] = [
    // 4
    PreflateParserConfig {
        good_length: 4,
        max_lazy: 4,
        nice_length: 16,
        max_chain: 16,
    },
    // 5
    PreflateParserConfig {
        good_length: 8,
        max_lazy: 16,
        nice_length: 32,
        max_chain: 32,
    },
    // 6
    PreflateParserConfig {
        good_length: 8,
        max_lazy: 16,
        nice_length: 128,
        max_chain: 128,
    },
    // 7
    PreflateParserConfig {
        good_length: 8,
        max_lazy: 32,
        nice_length: 128,
        max_chain: 256,
    },
    // 8
    PreflateParserConfig {
        good_length: 32,
        max_lazy: 128,
        nice_length: 258,
        max_chain: 1024,
    },
    // 9
    PreflateParserConfig {
        good_length: 32,
        max_lazy: 258,
        nice_length: 258,
        max_chain: 4096,
    }, // max compression
];
