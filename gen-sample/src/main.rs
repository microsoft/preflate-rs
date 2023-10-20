use std::fs::File;
use std::io::{self, Read, Write};
use std::{env, mem};

use libz_sys::{alloc_func, z_stream, zlibVersion, Z_DEFLATED};

fn main() -> io::Result<()> {
    // Define the input data that you want to compress
    // Get the command-line arguments
    let args: Vec<String> = env::args().collect();

    // Check if the correct number of arguments is provided
    if args.len() != 2 {
        println!("Usage: {} <input_file>", args[0]);
        return Ok(());
    }

    // Get the input file path from the command-line arguments
    let input_file_path = &args[1];

    // Read input data from the specified file
    let mut input_data = Vec::new();
    let mut input_file = File::open(input_file_path)?;
    input_file.read_to_end(&mut input_data)?;

    // Define compression levels (0 to 9)

    // Iterate over compression levels and create compressed files
    for level in 0..9 {
        // Create a file for each compression level
        let file_name = format!("compressed_miniz_oxide_level{}.bin", level);
        let mut file = File::create(file_name)?;

        // Compress data with the specified compression level
        let compressed_data = miniz_oxide::deflate::compress_to_vec(&input_data, level);

        // Get the compressed data and write it to the file
        file.write_all(&compressed_data)?;
    }

    // Iterate over compression levels and create compressed files
    for level in 0..9 {
        // Create a file for each compression level
        let file_name = format!("compressed_zlib_level{}.bin", level);
        let mut file = File::create(file_name)?;

        // Compress data with the specified compression level
        let mut output = Vec::new();
        output.resize(input_data.len() + 128, 0);

        let mut output_len = output.len() as u32;

        unsafe {
            // Initialize zlib parameters for raw deflate (window_bits = -15)
            let mut stream = libz_sys::z_stream {
                next_in: input_data.as_mut_ptr(),
                avail_in: input_data.len() as u32,
                next_out: output.as_mut_ptr(),
                avail_out: output.len() as u32,
                msg: std::ptr::null_mut(),
                state: std::ptr::null_mut(),
                zalloc: mem::transmute(0usize),
                zfree: mem::transmute(0usize),
                opaque: std::ptr::null_mut(),
                data_type: 0,
                adler: 0,
                reserved: 0,
                total_in: 0,
                total_out: 0,
            };

            let result = 
            // Initialize the deflate stream with window_bits set to -15 for raw deflate format
            libz_sys::deflateInit2_(
                &mut stream,
                level as i32,
                Z_DEFLATED,
                -15,
                8,
                0,
                zlibVersion(),
                std::mem::size_of::<z_stream>() as i32
            );

            libz_sys::deflate(&mut stream, 1);

            // Get the compressed data and write it to the file
            file.write_all(&output[0..stream.total_out as usize])?;
        }
    }

    Ok(())
}
