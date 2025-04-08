use std::{
    io::Cursor,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr::{null, null_mut},
};

use preflate_rs::{
    ExitCode, PreflateConfig, PreflateContainerProcessor, PreflateError, ProcessBuffer,
    RecreateContainerProcessor, ZstdCompressContext, ZstdDecompressContext,
};

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
/// can compare the preflate compression + zstd to just plain zstd compression)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_compression_context(flags: u32) -> *mut std::ffi::c_void {
    match catch_unwind_result(|| {
        let test_baseline = (flags & 0x10) != 0;
        let context = Box::new((
            12345678u32,
            CompressionContext::new(
                PreflateContainerProcessor::new(PreflateConfig::default()),
                (flags & 0xf) as i32,
                test_baseline,
            ),
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
        let x = Box::from_raw(context as *mut (u32, CompressionContext));
        assert_eq!(x.0, 12345678, "invalid context passed in");
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
            let context = context as *mut (u32, CompressionContext);
            let (magic, context) = &mut *context;
            assert_eq!(*magic, 12345678, "invalid context passed in");

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

            let mut writer = Cursor::new(output);
            let done = context.process_buffer(
                input,
                input_complete,
                &mut writer,
                output_buffer_size as usize,
            )?;

            *result_size = writer.position().into();
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
        let context = context as *mut (u32, CompressionContext);
        let (magic, context) = &*context;
        assert_eq!(*magic, 12345678, "invalid context passed in");

        let stats = context.stats();

        *deflate_compressed_size = stats.deflate_compressed_size;
        *zstd_compressed_size = stats.zstd_compressed_size;
        *zstd_baseline_size = stats.zstd_baseline_size;
        *uncompressed_size = stats.uncompressed_size;
        *overhead_bytes = stats.overhead_bytes;
        *hash_algorithm = stats.hash_algorithm.to_u16() as u32;
    }
}

type DecompressionContext = ZstdDecompressContext<RecreateContainerProcessor>;
type CompressionContext = ZstdCompressContext<PreflateContainerProcessor>;

/// Allocates new decompression context, must be freed with free_decompression_context
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_decompression_context(
    _flags: u32,
    capacity: u64,
) -> *mut std::ffi::c_void {
    match catch_unwind_result(|| {
        let context = Box::new((
            87654321u32,
            DecompressionContext::new(RecreateContainerProcessor::new(capacity as usize)),
        ));
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
        let x = Box::from_raw(context as *mut (u32, DecompressionContext));
        assert_eq!(x.0, 87654321, "invalid context passed in");
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
            let context = context as *mut (u32, DecompressionContext);
            let (magic, context) = &mut *context;
            assert_eq!(*magic, 87654321, "invalid context passed in");

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

            let mut writer = Cursor::new(output);
            let done = context.process_buffer(
                input,
                input_complete,
                &mut writer,
                output_buffer_size as usize,
            )?;

            *result_size = writer.position().into();
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
                std::ptr::null_mut(),
                0,
            );
            assert_eq!(retval, 0);

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
                std::ptr::null_mut(),
                0,
            );
            assert!(retval >= 0, "not expecting an error");

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
                std::ptr::null_mut(),
                0,
            );
            assert_eq!(retval, 0);

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
                std::ptr::null_mut(),
                0,
            );
            assert!(retval >= 0, "not expecting an error");

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

        assert!(retval == 0, "expecting no error");

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

        let len = error_string.iter().position(|&x| x == 0).unwrap();

        let error_string = std::ffi::CStr::from_bytes_with_nul(&error_string[0..len + 1]).unwrap();

        assert!(
            error_string
                .to_str()
                .unwrap()
                .starts_with("more data provided after input_complete signaled"),
        );
    }
}
