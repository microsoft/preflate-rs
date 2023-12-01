# preflate-rs
preflate-rs is a port of the C++ [preflate library](https://github.com/deus-libri/preflate/) to split deflate streams into uncompressed data and reconstruction information, or reconstruct the original deflate stream from those two.

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

The general approach is as follows:
1. Decompress stream into plaintext and a list of blocks containing tokens that are either literals (bytes) or distance, length pairs.
2. Estimation scan of content to estimate parameters used for compression. The better the estimation, the less corrections we need when we try to recreate the compression.
3. Rerun compression using the zlib algorithm using the parameters gathered above. A difference encoder is used to record each instance where the token predicted by our implementation of DEFLATE differs from what we found in the file. 

The following differences are corrected:
- Type of block (uncompressed, static huffman, dynamic huffman)
- Number of tokens in block (normally 16386)
- Dynamic huffman encoding (estimated using the zlib algorithm, but there are multiple ways to construct more or less optimal length limited Huffman codes)
- Literal vs (distance, length) pair (corrected by a single bit)
- Length or distance is incorrect (corrected by encoding the number of hops backwards until the correct one)
- Weird 258 length size (standard allows for two different encodings)

Note that the data formats of the recompression information are different and incompatible to the original preflate implemenation, as this library uses a different arithmetic encoder (shared from the Lepton JPEG compression library).

## How to Use This Library

#### Building From Source

- [Rust 1.70 or Above](https://www.rust-lang.org/tools/install)

```
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

Licensed under the [Apache 2.0](LICENSE) license.