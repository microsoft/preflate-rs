use std::{
    io::Cursor,
    panic::{catch_unwind, AssertUnwindSafe},
};

use crate::{
    preflate_error::ExitCode, PreflateCompressionContext, PreflateDecompressionContext,
    PreflateError,
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

#[no_mangle]
pub unsafe extern "C" fn create_compression_context(_flags: u32) -> *mut std::ffi::c_void {
    let context = Box::new((12345678u32, PreflateCompressionContext::new()));
    Box::into_raw(context) as *mut std::ffi::c_void
}

#[no_mangle]
pub unsafe extern "C" fn free_compression_context(context: *mut std::ffi::c_void) {
    let x = Box::from_raw(context as *mut (u32, PreflateCompressionContext));
    assert_eq!(x.0, 12345678, "invalid context passed in");
    // let Box destroy the object
}

/// Compresses a file using the preflate algorithm.
///
/// Returns -1 if more data is needed or if there is more data available, or 0 if done successfully.
/// Returns > 0 if there is an error
#[no_mangle]
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
    match catch_unwind_result(|| {
        let context = context as *mut (u32, PreflateCompressionContext);
        let (magic, context) = &mut *context;
        assert_eq!(*magic, 12345678, "invalid context passed in");

        let input = std::slice::from_raw_parts(input_buffer, input_buffer_size as usize);
        let output = std::slice::from_raw_parts_mut(output_buffer, output_buffer_size as usize);

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
        Ok(done) => {
            if done {
                0
            } else {
                -1
            }
        }
        Err(e) => {
            copy_cstring_utf8_to_buffer(
                e.message(),
                std::slice::from_raw_parts_mut(error_string, error_string_buffer_len as usize),
            );
            e.exit_code().as_integer_error_code()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn get_compression_stats(
    context: *mut std::ffi::c_void,
    compressed_size: *mut u64,
    uncompressed_size: *mut u64,
    overhead_bytes: *mut u64,
    hash_algorithm: *mut u32,
) {
    let context = context as *mut (u32, PreflateCompressionContext);
    let (magic, context) = &*context;
    assert_eq!(*magic, 12345678, "invalid context passed in");

    *compressed_size = context.compression_stats.compressed_size;
    *uncompressed_size = context.compression_stats.uncompressed_size;
    *overhead_bytes = context.compression_stats.overhead_bytes;
    *hash_algorithm = context.compression_stats.hash_algorithm.to_u16() as u32;
}

#[no_mangle]
pub unsafe extern "C" fn create_decompression_context(
    _flags: u32,
    capacity: u64,
) -> *mut std::ffi::c_void {
    let context = Box::new((
        87654321u32,
        PreflateDecompressionContext::new(capacity as usize),
    ));
    Box::into_raw(context) as *mut std::ffi::c_void
}

#[no_mangle]
pub unsafe extern "C" fn free_decompression_context(context: *mut std::ffi::c_void) {
    let x = Box::from_raw(context as *mut (u32, PreflateDecompressionContext));
    assert_eq!(x.0, 87654321, "invalid context passed in");
    // let Box destroy the object
}

/// Compresses a file using the preflate algorithm.
///
/// Returns -1 if more data is needed or if there is more data available, or 0 if done successfully.
/// Returns > 0 if there is an error
#[no_mangle]
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
    match catch_unwind_result(|| {
        let context = context as *mut (u32, PreflateDecompressionContext);
        let (magic, context) = &mut *context;
        assert_eq!(*magic, 87654321, "invalid context passed in");

        let input = std::slice::from_raw_parts(input_buffer, input_buffer_size as usize);
        let output = std::slice::from_raw_parts_mut(output_buffer, output_buffer_size as usize);

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
        Ok(done) => {
            if done {
                0
            } else {
                -1
            }
        }
        Err(e) => {
            copy_cstring_utf8_to_buffer(
                e.message(),
                std::slice::from_raw_parts_mut(error_string, error_string_buffer_len as usize),
            );
            e.exit_code().as_integer_error_code()
        }
    }
}

#[test]
fn extern_interface() {
    use crate::process::read_file;
    let input = read_file("samplezip.zip");

    let mut compressed = Vec::new();
    let empty = Vec::new();

    unsafe {
        let compression_context = create_compression_context(0);

        let mut compressed_chunk = Vec::new();
        compressed_chunk.resize(10000, 0);

        input.chunks(10000).for_each(|chunk| {
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
            assert_eq!(retval, -1);

            compressed.extend_from_slice(&compressed_chunk[..(result_size as usize)]);
        });

        loop {
            let mut result_size: u64 = 0;

            let retval = compress_buffer(
                compression_context,
                empty.as_ptr(),
                0,
                true,
                compressed_chunk.as_mut_ptr(),
                compressed_chunk.len() as u64,
                (&mut result_size) as *mut u64,
                std::ptr::null_mut(),
                0,
            );

            compressed.extend_from_slice(&compressed_chunk[..(result_size as usize)]);

            if retval == 0 {
                break;
            }
        }

        let mut overhead_bytes = 0;
        let mut uncompressed_size = 0;
        let mut compressed_size = 0;
        let mut hash_algorithm = 0;

        get_compression_stats(
            compression_context,
            &mut compressed_size,
            &mut uncompressed_size,
            &mut overhead_bytes,
            &mut hash_algorithm,
        );

        println!("stats: overhead={overhead_bytes}, uncompressed={uncompressed_size}, compressed={compressed_size} hash_algorithm={hash_algorithm}");

        free_compression_context(compression_context);
    }

    let mut original = Vec::new();

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
            assert_eq!(retval, -1);

            original.extend_from_slice(&decompressed_chunk[..(result_size as usize)]);
        });

        loop {
            let mut result_size: u64 = 0;

            let retval = decompress_buffer(
                decompression_context,
                empty.as_ptr(),
                0,
                true,
                decompressed_chunk.as_mut_ptr(),
                decompressed_chunk.len() as u64,
                (&mut result_size) as *mut u64,
                std::ptr::null_mut(),
                0,
            );

            original.extend_from_slice(&decompressed_chunk[..(result_size as usize)]);

            if retval == 0 {
                break;
            }
        }

        free_decompression_context(decompression_context);
    }

    assert_eq!(input.len() as u64, original.len() as u64);
    assert_eq!(input[..], original[..]);
}
