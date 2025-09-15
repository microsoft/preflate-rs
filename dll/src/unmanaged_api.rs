use std::{
    collections::VecDeque,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr::{null, null_mut},
};

use preflate_container::{
    PreflateContainerConfig, PreflateContainerProcessor, ProcessBuffer, RecreateContainerProcessor,
    ZstdCompressContext, ZstdDecompressContext, process_limited_buffer,
};
use preflate_rs::{ExitCode, PreflateError};

/// Helper function to catch panics and convert them into the appropriate LeptonError
fn catch_unwind_result<R>(
    f: impl FnOnce() -> Result<R, PreflateError>,
) -> Result<R, PreflateError> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r.map_err(|e| e.into()),
        Err(err) => {
            if let Some(message) = err.downcast_ref::<&str>() {
                Err(PreflateError::new(ExitCode::AssertionFailure, *message))
            } else if let Some(message) = err.downcast_ref::<String>() {
                Err(PreflateError::new(
                    ExitCode::AssertionFailure,
                    message.as_str(),
                ))
            } else {
                Err(PreflateError::new(
                    ExitCode::AssertionFailure,
                    "unknown panic",
                ))
            }
        }
    }
}

/// copies a string into a limited length zero terminated utf8 buffer
fn copy_cstring_utf8_to_buffer(str: &str, target_error_string: &mut [u8]) {
    if target_error_string.len() == 0 {
        return;
    }

    // copy error string into the buffer as utf8
    let b = std::ffi::CString::new(str).unwrap();
    let b = b.as_bytes();

    let copy_len = std::cmp::min(b.len(), target_error_string.len() - 1);

    // copy string into buffer as much as fits
    target_error_string[0..copy_len].copy_from_slice(&b[0..copy_len]);

    // always null terminated
    target_error_string[copy_len] = 0;
}

#[test]
fn test_copy_cstring_utf8_to_buffer() {
    // test utf8
    let mut buffer = [0u8; 10];
    copy_cstring_utf8_to_buffer("h\u{00E1}llo", &mut buffer);
    assert_eq!(buffer, [b'h', 0xc3, 0xa1, b'l', b'l', b'o', 0, 0, 0, 0]);

    // test null termination
    let mut buffer = [0u8; 10];
    copy_cstring_utf8_to_buffer("helloeveryone", &mut buffer);
    assert_eq!(
        buffer,
        [b'h', b'e', b'l', b'l', b'o', b'e', b'v', b'e', b'r', 0]
    );
}

/// Allocates new compression context, must be freed with free_compression_context
/// flags:
///  bits 0-4 zstd level to use (0-16)
///  bit 5: test baseline (does a baseline zstd compression of the input passed in so we
///     can compare the preflate compression + zstd to just plain zstd compression)
///  bit 6: if 1, skip verify after compress. This is useful if caller does a separate verify step after to save CPU time.
///     *If this is set, the caller must verify the data after decompressing it as in some cases it may be not decompress successfully.*
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_compression_context(flags: u32) -> *mut std::ffi::c_void {
    match catch_unwind_result(|| {
        let compression_level = (flags & 0xf) as i32;
        let test_baseline = (flags & 0x10) != 0;
        let verify = (flags & 0x20) != 0;

        let context = Box::new(CompressionContext::new(
            verify,
            compression_level,
            test_baseline,
        ));

        Ok(Box::into_raw(context) as *mut std::ffi::c_void)
    }) {
        Ok(context) => context,
        Err(e) => {
            eprintln!("error creating compression context: {}", e.message());
            null_mut()
        }
    }
}

/// Frees the compression context
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_compression_context(context: *mut std::ffi::c_void) {
    unsafe {
        let x = Box::from_raw(context as *mut CompressionContext);
        assert_eq!(
            x.magic, MAGIC_COMPRESSION_CONTEXT,
            "invalid context passed in"
        );
        // let Box destroy the object. If this asserts, we have some kind of memory corruption so better to just kill the process.
    }
}

/// Compresses a file using the preflate algorithm.
///
/// Returns 0 if more data is needed or if there is more data available, or 1 if done successfully.
/// Returns < 0 if there is an error (negative value is the error code)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn compress_buffer(
    context: *mut std::ffi::c_void,
    input_buffer: *const u8,
    input_buffer_size: u64,
    input_complete: bool,
    output_buffer: *mut u8,
    output_buffer_size: u64,
    result_size: *mut u64,
    error_string: *mut std::os::raw::c_uchar,
    error_string_buffer_len: u64,
) -> i32 {
    unsafe {
        match catch_unwind_result(|| {
            let context = CompressionContext::from_pointer(context);

            let input = if input_buffer == null() {
                &[]
            } else {
                std::slice::from_raw_parts(input_buffer, input_buffer_size as usize)
            };
            let output = if output_buffer == null_mut() {
                &mut []
            } else {
                std::slice::from_raw_parts_mut(output_buffer, output_buffer_size as usize)
            };

            let (done, buffer_written) = process_limited_buffer(
                &mut context.internal,
                input,
                input_complete,
                output,
                &mut context.output_extra,
            )?;

            *result_size = buffer_written as u64;
            Ok(done)
        }) {
            Ok(done) => done as i32,
            Err(e) => {
                if error_string != null_mut() {
                    copy_cstring_utf8_to_buffer(
                        e.message(),
                        std::slice::from_raw_parts_mut(
                            error_string,
                            error_string_buffer_len as usize,
                        ),
                    );
                }
                -e.exit_code().as_integer_error_code()
            }
        }
    }
}

/// returns the compression statistics associated with the compression context
#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_compression_stats(
    context: *mut std::ffi::c_void,
    deflate_compressed_size: *mut u64,
    zstd_compressed_size: *mut u64,
    zstd_baseline_size: *mut u64,
    uncompressed_size: *mut u64,
    overhead_bytes: *mut u64,
    hash_algorithm: *mut u32,
) {
    unsafe {
        let context = CompressionContext::from_pointer(context);

        let stats = context.internal.stats();

        *deflate_compressed_size = stats.deflate_compressed_size;
        *zstd_compressed_size = stats.zstd_compressed_size;
        *zstd_baseline_size = stats.zstd_baseline_size;
        *uncompressed_size = stats.uncompressed_size;
        *overhead_bytes = stats.overhead_bytes;
        *hash_algorithm = stats.hash_algorithm.to_u16() as u32;
    }
}

struct CompressionContext {
    magic: u32,
    internal: ZstdCompressContext<PreflateContainerProcessor>,
    output_extra: VecDeque<u8>,
}

const MAGIC_DECOMRESSION_CONTEXT: u32 = 87654321;
const MAGIC_COMPRESSION_CONTEXT: u32 = 12345678;

impl CompressionContext {
    fn from_pointer(ptr: *mut std::ffi::c_void) -> &'static mut Self {
        unsafe {
            let context = ptr as *mut CompressionContext;
            assert_eq!(
                (*context).magic,
                MAGIC_COMPRESSION_CONTEXT,
                "invalid context passed in"
            );
            &mut *context
        }
    }

    fn new(verify: bool, compression_level: i32, test_baseline: bool) -> Self {
        CompressionContext {
            magic: MAGIC_COMPRESSION_CONTEXT,
            internal: ZstdCompressContext::new(
                PreflateContainerProcessor::new(&PreflateContainerConfig {
                    validate_compression: verify,
                    max_chain_length: 1024, // lower max chain to avoid excessive CPU usage
                    ..PreflateContainerConfig::default()
                }),
                compression_level,
                test_baseline,
            ),
            output_extra: VecDeque::new(),
        }
    }
}

struct DecompressionContext {
    magic: u32,
    internal: ZstdDecompressContext<RecreateContainerProcessor>,
    output_extra: VecDeque<u8>,
}

impl DecompressionContext {
    fn from_pointer(ptr: *mut std::ffi::c_void) -> &'static mut Self {
        unsafe {
            let context = ptr as *mut DecompressionContext;
            assert_eq!(
                (*context).magic,
                MAGIC_DECOMRESSION_CONTEXT,
                "invalid context passed in"
            );
            &mut *context
        }
    }

    fn new(capacity: usize) -> Self {
        let internal = ZstdDecompressContext::new(RecreateContainerProcessor::new(capacity));

        DecompressionContext {
            magic: MAGIC_DECOMRESSION_CONTEXT,
            internal,
            output_extra: VecDeque::new(),
        }
    }
}

/// Allocates new decompression context, must be freed with free_decompression_context
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_decompression_context(
    _flags: u32,
    capacity: u64,
) -> *mut std::ffi::c_void {
    match catch_unwind_result(|| {
        let context = Box::new(DecompressionContext::new(capacity as usize));
        Ok(Box::into_raw(context) as *mut std::ffi::c_void)
    }) {
        Ok(context) => context,
        Err(e) => {
            eprintln!("error creating decompression context: {}", e.message());
            null_mut()
        }
    }
}

/// Frees the decompression context
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_decompression_context(context: *mut std::ffi::c_void) {
    unsafe {
        let x = Box::from_raw(context as *mut DecompressionContext);
        assert_eq!(
            x.magic, MAGIC_DECOMRESSION_CONTEXT,
            "invalid context passed in"
        );
        // let Box destroy the object
    }
}

/// Recreates the original file using the preflate algorithm.
///
/// Returns 0 if more data is needed or if there is more data available, or 1 if done successfully.
/// Returns < 0 if there is an error (negative value is the error code)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn decompress_buffer(
    context: *mut std::ffi::c_void,
    input_buffer: *const u8,
    input_buffer_size: u64,
    input_complete: bool,
    output_buffer: *mut u8,
    output_buffer_size: u64,
    result_size: *mut u64,
    error_string: *mut std::os::raw::c_uchar,
    error_string_buffer_len: u64,
) -> i32 {
    unsafe {
        match catch_unwind_result(|| {
            let context = DecompressionContext::from_pointer(context);

            let input = if input_buffer == null() {
                &[]
            } else {
                std::slice::from_raw_parts(input_buffer, input_buffer_size as usize)
            };
            let output = if output_buffer == null_mut() {
                &mut []
            } else {
                std::slice::from_raw_parts_mut(output_buffer, output_buffer_size as usize)
            };

            let (done, buffer_written) = process_limited_buffer(
                &mut context.internal,
                input,
                input_complete,
                output,
                &mut context.output_extra,
            )?;

            *result_size = buffer_written as u64;
            Ok(done)
        }) {
            Ok(done) => done as i32,
            Err(e) => {
                copy_cstring_utf8_to_buffer(
                    e.message(),
                    std::slice::from_raw_parts_mut(error_string, error_string_buffer_len as usize),
                );
                -e.exit_code().as_integer_error_code()
            }
        }
    }
}

#[cfg(test)]
pub fn read_file(filename: &str) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    let filename = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("samples")
        .join(filename);
    println!("reading {0}", filename.to_str().unwrap());
    let mut f = File::open(filename).unwrap();

    let mut content = Vec::new();
    f.read_to_end(&mut content).unwrap();

    content
}

#[test]
fn extern_interface() {
    let original = read_file("samplezip.zip");

    let mut compressed = Vec::new();
    let error_string = &mut [0u8; 1024];

    unsafe {
        let compression_context = create_compression_context(1);

        let mut compressed_chunk = Vec::new();
        compressed_chunk.resize(10000, 0);

        original.chunks(10000).for_each(|chunk| {
            let mut result_size: u64 = 0;

            let retval = compress_buffer(
                compression_context,
                chunk.as_ptr(),
                chunk.len() as u64,
                false,
                compressed_chunk.as_mut_ptr(),
                compressed_chunk.len() as u64,
                (&mut result_size) as *mut u64,
                error_string.as_mut_ptr(),
                error_string.len() as u64,
            );
            assert!(
                retval == 0,
                "expecting no error {} {:?}",
                retval,
                get_cstring(&error_string)
            );

            compressed.extend_from_slice(&compressed_chunk[..(result_size as usize)]);
        });

        loop {
            let mut result_size: u64 = 0;

            let retval = compress_buffer(
                compression_context,
                null(),
                0,
                true,
                compressed_chunk.as_mut_ptr(),
                compressed_chunk.len() as u64,
                (&mut result_size) as *mut u64,
                error_string.as_mut_ptr(),
                error_string.len() as u64,
            );
            assert!(
                retval >= 0,
                "expecting no error {} {:?}",
                retval,
                get_cstring(&error_string)
            );

            compressed.extend_from_slice(&compressed_chunk[..(result_size as usize)]);

            if retval == 1 {
                break;
            }
        }

        let mut overhead_bytes = 0;
        let mut uncompressed_size = 0;
        let mut deflate_compressed_size = 0;
        let mut zstd_compressed_size = 0;
        let mut zstd_baseline_size = 0;
        let mut hash_algorithm = 0;

        get_compression_stats(
            compression_context,
            &mut deflate_compressed_size,
            &mut zstd_compressed_size,
            &mut zstd_baseline_size,
            &mut uncompressed_size,
            &mut overhead_bytes,
            &mut hash_algorithm,
        );

        println!(
            "stats: overhead={overhead_bytes}, uncompressed={uncompressed_size}, deflate_compressed={deflate_compressed_size} zstd_compressed={zstd_compressed_size}, zstd_baseline={zstd_baseline_size} hash_algorithm={hash_algorithm}"
        );

        free_compression_context(compression_context);
    }

    let mut recreated = Vec::new();

    unsafe {
        let decompression_context = create_decompression_context(0, 1024 * 1024 * 50);

        let mut decompressed_chunk = Vec::new();
        decompressed_chunk.resize(10000, 0);

        compressed.chunks(10000).for_each(|chunk| {
            let mut result_size: u64 = 0;

            let retval = decompress_buffer(
                decompression_context,
                chunk.as_ptr(),
                chunk.len() as u64,
                false,
                decompressed_chunk.as_mut_ptr(),
                decompressed_chunk.len() as u64,
                (&mut result_size) as *mut u64,
                error_string.as_mut_ptr(),
                error_string.len() as u64,
            );
            assert!(
                retval == 0,
                "expecting no error {} {:?}",
                retval,
                get_cstring(&error_string)
            );

            recreated.extend_from_slice(&decompressed_chunk[..(result_size as usize)]);
        });

        loop {
            let mut result_size: u64 = 0;

            let retval = decompress_buffer(
                decompression_context,
                null(),
                0,
                true,
                decompressed_chunk.as_mut_ptr(),
                decompressed_chunk.len() as u64,
                (&mut result_size) as *mut u64,
                error_string.as_mut_ptr(),
                error_string.len() as u64,
            );

            assert!(
                retval >= 0,
                "expecting no error {} {:?}",
                retval,
                get_cstring(&error_string)
            );

            recreated.extend_from_slice(&decompressed_chunk[..(result_size as usize)]);

            if retval == 1 {
                break;
            }
        }

        free_decompression_context(decompression_context);
    }

    assert_eq!(original.len() as u64, recreated.len() as u64);
    assert_eq!(original[..], recreated[..]);
}

/// tests the error message translation
#[test]
fn test_error_translation() {
    unsafe {
        let compression_context = create_compression_context(1);

        let chunk = vec![1, 2, 3];
        let mut result_size: u64 = 0;
        let mut error_string = [0u8; 100];

        let retval = compress_buffer(
            compression_context,
            chunk.as_ptr(),
            chunk.len() as u64,
            true,
            null_mut(),
            0,
            (&mut result_size) as *mut u64,
            error_string.as_mut_ptr(),
            error_string.len() as u64,
        );

        assert!(
            retval == 0,
            "expecting no error {} {:?}",
            retval,
            get_cstring(&error_string)
        );

        let retval = compress_buffer(
            compression_context,
            chunk.as_ptr(),
            chunk.len() as u64,
            false,
            null_mut(),
            0,
            (&mut result_size) as *mut u64,
            error_string.as_mut_ptr(),
            error_string.len() as u64,
        );

        assert_eq!(retval, -(ExitCode::InvalidParameter as i32));

        let error_string = get_cstring(&error_string);

        assert!(
            error_string
                .to_str()
                .unwrap()
                .starts_with("more data provided after input_complete signaled"),
        );
    }
}

/// helper to get a cstring from a fixed size array for testing (finds zero terminator)
#[cfg(test)]
fn get_cstring<'a, const N: usize>(error_string: &'a [u8; N]) -> &'a std::ffi::CStr {
    let len = error_string.iter().position(|&x| x == 0).unwrap();

    let error_string = std::ffi::CStr::from_bytes_with_nul(&error_string[0..len + 1]).unwrap();
    error_string
}
