# preflate-rs
Preflate-rs is a library initally based on a port of the C++ [preflate library](https://github.com/deus-libri/preflate/) with the purpose of splitting deflate streams into uncompressed data and reconstruction information, or reconstruct the original deflate stream from those two.

Other similar libraries include precomp, reflate, grittibanzli, although this libary is probably the most feature rich and supports a lower overhead from more libraries.

IMPORTANT: This library is still in initial development, so there are probably breaking changes being done fairly frequently.

The resulting uncompressed content can then be recompressed by a more modern compression technique such as Zstd, lzma, etc. This library is designed to be used as part of a cloud
storage system that requires exact binary storage of content, so the libary needs to make
sure that the DEFLATE content is recreated exactly as it was written. This is not trivial, since
DEFLATE has a large degree of freedom in choosing both how the distance/length pairs are chose
and how the Huffman trees are created.

The library tries to detect the following compressors to try to do a reasonable job:
- [Zlib](https://github.com/madler/zlib): Zlib is more or less perfectly compressed.
- [MiniZ](https://github.com/richgel999/miniz): The fastest mode uses a different hash function.
- [Libdeflate](https://github.com/ebiggers/libdeflate): This library uses 4 byte hash-tables, which we try to detect.
- [Libzng](https://github.com/zlib-ng/zlib-ng): Works well except level 9
- Windows zlib implementation (used by the built-in PNG codec and shell ZIP compression) 

The general approach is as follows:
1. Decompress stream into plaintext and a list of blocks containing tokens that are either literals (bytes) or distance, length pairs.
2. Estimate the dictionary update strategy by looking at which strings are referenced by the compressed data. For example, zlib will only add the beginning of each compressed token for low compression levels.
3. Estimate the maximum number times we execute the loop to look for matches (also called chains, as in walking the chain of the hash table). We also test with different hash functions to figure out which hash funciton was likely used. Given the chain length, we estimate the other parameters that were likely used.
4. Rerun compression using the zlib algorithm using the parameters gathered above. A difference encoder is used to record each instance where the token predicted by our implementation of DEFLATE differs from what we found in the file. 

The following differences are corrected:
- Type of block (uncompressed, static huffman, dynamic huffman)
- Number of tokens in block (normally 16385)
- Dynamic huffman encoding (estimated using the zlib algorithm, but there are multiple ways to construct more or less optimal length limited Huffman codes)
- Literal vs (distance, length) pair (corrected by a single bit)
- Length or distance is incorrect (corrected by encoding the number of hops backwards until the correct one)

Note that the data formats of the recompression information are different and incompatible to the original preflate implementation, as this library uses a different arithmetic encoder (shared from the Lepton JPEG compression library).

### Overhead

In order to faithfully recreate the exact deflate stream, the library stores
a stream of corrections to its predictive model. Depending on how good the
predictive model is, the corrections can take up more or less space. If you
want to improve the library, it's probably worth targetting the lower compression
levels that currently have significant overhead.

The amount of overhead vs uncompressed data is approximately the following,
depending on the compression level. If you want to benefit from using this
library, whatever better compression algorithm you use needs to be at least
that much better to make it worthwhile to recompress. 

| Library            | 0      | 1      | 2      | 3      | 4      | 5      | 6      | 7      | 8      | 9     |
|--------------------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|
| **zlib**           | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.08%  | 0.03%  | 0.01%  |
| **libngz**      | 0.01%  | 0.01%  | 0.01%  | 0.01%  | 0.97%  | 1.07%  | 0.90%  | 0.01%  | 0.01%  | NoCompressionCandidates |
| **libdeflate**     | 0.01%  | 0.25%  | 1.04%  | 0.91%  | 1.51%  | 1.04%  | 0.96%  | 0.87%  | 1.04%  | 1.03%  |
| **miniz_oxide**    | 0.01%  | 0.06%  | 2.70%  | 1.78%  | 0.53%  | 0.30%  | 0.09%  | 0.06%  | 0.08%  | 0.07%  |

## How to Use This Library

#### Building From Source

- [Rust 1.70 or Above](https://www.rust-lang.org/tools/install)

```Shell
git clone https://github.com/microsoft/preflate-rs
cd preflate-rs
cargo build
cargo test
cargo build --release
```

#### Running

There is an `preflate_util.exe` wrapper that is built as part of the project that can be used to
test out the library against Deflate compressed content. 

## Contributing

There are many ways in which you can participate in this project, for example:

* [Submit bugs and feature requests](https://github.com/microsoft/preflate-rs/issues), and help us verify as they are checked in
* Review [source code changes](https://github.com/microsoft/preflate-rs/pulls) or submit your own features as pull requests.
* The library uses only **stable features**. 

## Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## License

Copyright (c) Microsoft Corporation. All rights reserved.

Licensed under the Apache 2.0 license.