# Safe Context-adaptive binary arithmetic coding (CABAC) encoder / decoder in Rust

This crate is part of the [preflate-rs workspace](../README.md).
Its package version is maintained independently from the root workspace.
Dependency versions are inherited from the root `[workspace.dependencies]`,
including the `byteorder` version shared with preflate and container.

From the workspace root:

```text
cargo build --all
cargo test --all
cargo test -p cabac --all-features
cargo bench -p cabac --bench benches
cargo run --release -p cabac -- vp8
```

The optional `simd` feature remains disabled by default.

The profiling binary accepts `vp8`, `rans`, `fpaq`, or `all` to select its
repeated encode/decode workload; it is not a file compressor.

## Licensing

CABAC code authored by Kristof Roomp is licensed under Apache-2.0 as part of this
move, as authorized by the author. See the [repository LICENSE](../LICENSE).
The VP8 implementation retains its third-party BSD notices and license text in
[`src/vp8.rs`](src/vp8.rs).

## Implementation

Implementation of CABAC using VP8, rANS and Fpaq0 encoders.

The coder is designed to encode binary values in an efficient manner, taking into account the
bits that were previously seen. The previous state is stored in the Context object,
which is updated each time a bit is seen. Normally multi-bit symbols are converted
to binary form, and each bit is assigned a corresponding bin (which gets its own context).
Bits that are expected to be random can use the "bypass" mode, which are very efficiently
added to the bitstream without a context.

In order to decode the bitstream, the same contexts need to be used in the exact same sequence
or you will get back garbage. This also includes any bypass bits that must also be read in the
same exact order.

There are three encoder families included:
- VP8 CABAC which uses a 16-bit state to track what it has seen.
- rANS encoder (based on ryg_rans and dropbox/lepton) that uses the VP8 state to track probability
- Fpaq0 arithmetic encoder which has some nice properties since it is fast, carryless and can be run in parallel similar to the rANS. The parallel mode allows for interleaving of arbitrary bitstreams as long as the bitstreams are written in the same order as the bits are encoded.

Performance notes:
- Criterion bench tests included
- No unsafe code
- The optional `wide`-based SIMD implementation is available for parallel Fpaq0 decoding.
- Relative throughput depends on the workload and target CPU; use the benchmarks
  above rather than assuming that SIMD or any particular encoder is faster.

These historical upstream measurements (microseconds, lower is better) used an
Intel i9-12900K compiled with `-Ctarget-cpu=native`; they have not been remeasured
for this workspace:

| Encoder       | Read | Read bypass | Write |
| ------------- | ---- | ----------- | ----- |
| VP8           | 288  | 149         | 229   |
| rANS          | 162  | 59          | 190   |
| Fpaq0         | 241  |             | 177   |
| Fpaq0 parallel| 181  |             | 247   |
