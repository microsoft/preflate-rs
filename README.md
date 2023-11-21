# preflate-rs
preflate-rs is a port of the C++ [preflate library](https://github.com/deus-libri/preflate/) to split deflate streams into uncompressed data and reconstruction information, or reconstruct the original deflate stream from those two.

The resulting uncompressed content can then be recompressed by a more modern compression technique such as Zstd, lzma, etc. This library is designed to be used as part of a cloud
storage system that requires exact binary storage of content, so the libary needs to make
sure that the Deflate content is recreated exactly as it was written. This is not trivial, since
Default has a large degree of freedom in choosing both how the distance/length pairs are chose
and how the Huffman trees are created.

## How to Use This Library

#### Building From Source

- [Rust 1.65 or Above](https://www.rust-lang.org/tools/install)

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