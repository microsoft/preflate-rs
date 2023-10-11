mod bit_helper;
mod huffman_decoder;
mod huffman_helper;
mod preflate_block_decoder;
mod preflate_complevel_estimator;
mod preflate_constants;
mod preflate_hash_chain;
mod preflate_input;
mod preflate_parameter_estimator;
mod preflate_parse_config;
mod preflate_predictor_state;
mod preflate_seq_chain;
mod preflate_statistical_codec;
mod preflate_statistical_model;
mod preflate_stream_info;
mod preflate_token;
mod preflate_token_predictor;
mod preflate_tree_predictor;
mod zip_bit_reader;

use anyhow::{self, Context};
use byteorder::{LittleEndian, ReadBytesExt};
use preflate_block_decoder::PreflateBlockDecoder;
use std::{
    env,
    fs::File,
    io::{BufReader, Cursor, Read, Seek, SeekFrom},
};

mod crc32;
mod zip_structs;

use crate::{
    crc32::Crc32,
    preflate_parameter_estimator::estimate_preflate_parameters,
    preflate_statistical_model::PreflateStatisticsCounter,
    preflate_token_predictor::PreflateTokenPredictor,
    zip_structs::{
        Zip64ExtendedInformation, ZipCentralDirectoryFileHeader, ZipEndOfCentralDirectoryRecord,
        ZipExtendedInformationHeader, ZipLocalFileHeader,
    },
};

/// Read the Data Descriptor binaryReader is position to. Uses heuristic to detect Zip64 variant by looking for signature of next block (Local Header or Zip Central Directory)
fn fread_data_descriptor<R: Read + Seek>(
    binary_reader: &mut R,
    crc: &mut u32,
    compressed_size: &mut u64,
    uncompressed_size: &mut u64,
) -> anyhow::Result<bool> {
    let current_position = binary_reader.stream_position()?;

    // Check for signature of next block assuming regular zip format
    binary_reader.seek(SeekFrom::Current(12))?;
    let mut signature_next_block = binary_reader.read_u32::<LittleEndian>()?;

    if signature_next_block == zip_structs::ZIP_LOCAL_FILE_HEADER_SIGNATURE
        || signature_next_block == zip_structs::ZIP_CENTRAL_DIRECTORY_SIGNATURE
    {
        // Regular zip Data Descriptor case
        binary_reader.seek(SeekFrom::Start(current_position))?;
        *crc = binary_reader.read_u32::<LittleEndian>()?;
        *compressed_size = binary_reader.read_u32::<LittleEndian>()? as u64;
        *uncompressed_size = binary_reader.read_u32::<LittleEndian>()? as u64;
        return Ok(true);
    }

    // Check for signature of next block assuming Zip64 format
    binary_reader.seek(SeekFrom::Start(current_position + 20))?;
    signature_next_block = binary_reader.read_u32::<LittleEndian>()?;

    if signature_next_block == zip_structs::ZIP_LOCAL_FILE_HEADER_SIGNATURE
        || signature_next_block == zip_structs::ZIP_CENTRAL_DIRECTORY_SIGNATURE
    {
        // Zip64 Data Descriptor case
        binary_reader.seek(SeekFrom::Start(current_position))?;
        *crc = binary_reader.read_u32::<LittleEndian>()?;
        *compressed_size = binary_reader.read_u64::<LittleEndian>()?;
        *uncompressed_size = binary_reader.read_u64::<LittleEndian>()?;
        return Ok(true);
    }

    *crc = 0;
    *compressed_size = 0;
    *uncompressed_size = 0;
    return Ok(false);
}

fn analyze_compressed_data<R: Read + Seek>(
    binary_reader: &mut R,
    compressed_size_in_bytes: u64,
    header_crc32: u32,
    deflate_info_dump_level: i32,
    uncompressed_size: &mut u64,
) -> anyhow::Result<()> {
    let mut output_data: Vec<u8> = vec![0; 4096];
    let output_stream = Cursor::new(&mut output_data);
    let mut crc32 = Crc32::new();

    let mut block_decoder =
        PreflateBlockDecoder::new(binary_reader, compressed_size_in_bytes as i64)?;

    let mut blocks = Vec::new();
    let mut last = false;
    while !last {
        let block = block_decoder.read_block(&mut last, &mut crc32)?;

        if deflate_info_dump_level > 0 {
            // Log information about this deflate compressed block
            println!("Block: tokens={}", block.tokens.len());
        }

        blocks.push(block);
    }

    let params_e = estimate_preflate_parameters(&block_decoder.output, 0, &blocks);
    println!("prediction parameters: w {}, c {}, m {}, zlib {}, farL3M {}, very far M {}, M2S {}, log2CD {}",
            params_e.window_bits, params_e.comp_level, params_e.mem_level,
            params_e.zlib_compatible, params_e.far_len3_matches_detected,
            params_e.very_far_matches_detected, params_e.matches_to_start_detected,
            params_e.log2_of_max_chain_depth_m1);

    let mut counterE = PreflateStatisticsCounter::default();

    let mut tokenPredictorE = PreflateTokenPredictor::new(&block_decoder.output, &params_e, 0);

    for i in 0..blocks.len() {
        tokenPredictorE
            .analyze_block(i, &blocks[i])
            .with_context(|| format!("analyze_block {}", i))?;
        tokenPredictorE.update_counters(&mut counterE, i as u32);
    }

    if header_crc32 == 0 {
        if deflate_info_dump_level > 0 {
            println!("CRC: {:8X}", crc32.finalize_and_return_crc());
        }
    } else if crc32.finalize_and_return_crc() != header_crc32 {
        println!(
            "Header CRC: {:8X} != Data CRC: {:8X}...Possible CORRUPT FILE.",
            header_crc32,
            crc32.finalize_and_return_crc()
        );
    } else if deflate_info_dump_level > 0 {
        println!(
            "Header CRC: {0:8X} == Data CRC: {:8X}",
            crc32.finalize_and_return_crc()
        );
    }

    *uncompressed_size = output_stream.position();

    Ok(())
}

fn main_with_result() -> anyhow::Result<()> {
    const NUMBER_OF_SIZE_BUCKETS: i32 = 16;
    let mut zip_file_compressed_size_buckets: [[u64; 2]; 16] = [
        [0x400, 0],
        [0x800, 0],
        [0xc00, 0],
        [0x1000, 0],
        [0x2000, 0],
        [0x4000, 0],
        [0x8000, 0],
        [0x10000, 0],
        [0x20000, 0],
        [0x40000, 0],
        [0x80000, 0],
        [0x100000, 0],
        [0x200000, 0],
        [0x400000, 0],
        [0x800000, 0],
        [0x80000000, 0],
    ];

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1].eq_ignore_ascii_case("-?") {
        show_help();
        return Err(anyhow::Error::msg("Show Usage Run"));
    }

    let mut filename = String::from("");
    let mut check_data_crc = false;
    let mut deflate_info_dump_level = 0;

    for i in 1..args.len() {
        let arg = &args[i];

        if arg.ends_with("-v") {
            if deflate_info_dump_level == 0 {
                deflate_info_dump_level = 1;
            }
        } else if arg.ends_with("-x") {
            deflate_info_dump_level = 2;
        } else if arg.eq("-c") {
            check_data_crc = true;
        } else if !arg.starts_with("-") {
            filename = arg.to_string();
        }
    }

    if filename.is_empty() {
        return Err(anyhow::Error::msg("File name not provided"));
    }

    let mut file_in = File::open(&filename)?;
    let file_length = file_in.seek(SeekFrom::End(0))?;
    file_in.seek(SeekFrom::Start(0))?;

    let mut binary_reader = BufReader::new(file_in);
    let mut is_file_corrupt = false;
    let mut zip_local_file_headers = Vec::<ZipLocalFileHeader>::new();
    let mut zip_local_file_header_paths = Vec::<String>::new();
    let mut signature;
    let mut log_string: String;

    println!("Looking for inline Zip Headers");
    loop {
        // read the signature
        let mut zip_local_file_header = ZipLocalFileHeader::create_and_load(&mut binary_reader)?;
        signature = zip_local_file_header.local_file_header_signature;
        if signature != zip_structs::ZIP_LOCAL_FILE_HEADER_SIGNATURE {
            if zip_local_file_headers.len() == 0 {
                return Err(anyhow::Error::msg("No Zip Headers Found...Not a Zip file"));
            }

            binary_reader
                .seek_relative(-(zip_structs::ZIP_LOCAL_FILE_HEADER_SIZE_IN_BYTES as i64))?; // rewind to start of header
            break;
        }

        zip_local_file_headers.push(ZipLocalFileHeader::clone(&zip_local_file_header)); // clone to prevent move

        // read extended information
        let mut file_name_buf = Vec::<u8>::new();
        file_name_buf.resize(zip_local_file_header.file_name_length as usize, 0);
        binary_reader.read_exact(&mut file_name_buf)?;
        let path = String::from_utf8(file_name_buf)?;

        zip_local_file_header_paths.push(path.clone()); // save the file name for compare with central, clone to prevent move

        let mut zip_local_file_header_and_data_size_in_bytes =
            zip_structs::ZIP_LOCAL_FILE_HEADER_SIZE_IN_BYTES as u64
                + zip_local_file_header.file_name_length as u64
                + zip_local_file_header.extra_field_length as u64
                + zip_local_file_header.compressed_size as u64;

        if zip_local_file_headers.len() == 1 {
            println!("Found inline Zip Header... Dumping inline zip headers\n");
            println!(
                "{:-3}{:8}{:8}{:8}{:8} Path",
                "", "CSize", "UCSize", "XSize", "cbTotal"
            );
        }

        log_string = format!(
            "{:-3}{:8}{:8}{:8}{:8} {}",
            zip_local_file_headers.len(),
            zip_local_file_header.compressed_size,
            zip_local_file_header.uncompressed_size,
            zip_local_file_header.extra_field_length,
            zip_local_file_header_and_data_size_in_bytes,
            &path
        );

        // Extra field
        let pos_local_header_extra_field_max =
            binary_reader.stream_position()? + zip_local_file_header.extra_field_length as u64;
        while binary_reader.stream_position()? < pos_local_header_extra_field_max {
            // Expect a ZipExtendedInformationHeader
            let zip_extended_information_header =
                ZipExtendedInformationHeader::create_and_load(&mut binary_reader)?;

            // Do we recognize the type?
            if zip_extended_information_header.header_id
                == zip_structs::ZIP64_EXTENDED_INFORMATION_TYPE_TAG
            {
                // Load the Zip64ExtendedInformation..this will consume DataSize bytes even if there is an error
                let zip64_extended_information = Zip64ExtendedInformation::create_and_load(
                    &mut binary_reader,
                    false,
                    zip_extended_information_header.data_size as u32,
                    zip_local_file_header.uncompressed_size as u32,
                    zip_local_file_header.compressed_size as u32,
                    0,
                    0,
                )?;

                zip_local_file_header.uncompressed_size = zip64_extended_information.size_original;
                zip_local_file_header.compressed_size = zip64_extended_information.size_compressed;
                log_string = format!(
                    "{:-3}{:8}{:8}{:8}{:8} {}::Zip64",
                    zip_local_file_headers.len(),
                    zip_local_file_header.compressed_size,
                    zip_local_file_header.uncompressed_size,
                    zip_local_file_header.extra_field_length,
                    zip_local_file_header_and_data_size_in_bytes,
                    &path
                );

                // No need to skip forward as ZipExtendedInformationHeader.DataSize bytes were consumed by load above
            } else {
                // Just skip over it
                binary_reader.seek_relative(zip_extended_information_header.data_size as i64)?;
            }
        }

        // Handle the compressed DATA. Currently only Deflate (8) and uncompressed (0) are supported.
        if zip_local_file_header.compression_method == 8 {
            // Deflate
            // Need to decompress the data if asked to or if the file has a DataDescriptor after the compressed data and thus no value for Compressed Size
            if deflate_info_dump_level > 0
                || check_data_crc
                || zip_local_file_header.fhas_data_descriptor()
            {
                let start_position = binary_reader.stream_position()?;
                let mut uncompressed_size: u64 = 0;

                if deflate_info_dump_level > 0 {
                    println!("{}", &log_string);
                    log_string = "<<End>>".to_string();
                }

                let compressed_size = match zip_local_file_header.fhas_data_descriptor() {
                    true => u64::MAX,
                    false => zip_local_file_header.compressed_size,
                };

                analyze_compressed_data(
                    &mut binary_reader,
                    compressed_size,
                    zip_local_file_header.crc32,
                    deflate_info_dump_level,
                    &mut uncompressed_size,
                )?;

                if zip_local_file_header.fhas_data_descriptor() {
                    let start_position_dd = binary_reader.stream_position()?;

                    if binary_reader.read_u32::<LittleEndian>()? == 0x08074b50
                        && fread_data_descriptor(
                            &mut binary_reader,
                            &mut zip_local_file_header.crc32,
                            &mut zip_local_file_header.compressed_size,
                            &mut zip_local_file_header.uncompressed_size,
                        )?
                    {
                        zip_local_file_header_and_data_size_in_bytes +=
                            zip_local_file_header.compressed_size;

                        log_string = format!(
                            "{:-3}{:8}{:8}{:8}{:8} {}::DD",
                            zip_local_file_headers.len(),
                            zip_local_file_header.compressed_size,
                            zip_local_file_header.uncompressed_size,
                            zip_local_file_header.extra_field_length,
                            zip_local_file_header_and_data_size_in_bytes,
                            &path
                        );
                    } else
                    // if there isn't a Data Descriptor we can fill in the compressedSize and uncompressed size from the results of the Deflate uncompress
                    {
                        binary_reader.seek(SeekFrom::Start(start_position_dd))?;
                        zip_local_file_header.compressed_size =
                            binary_reader.stream_position()? - start_position;
                        zip_local_file_header.uncompressed_size = uncompressed_size;
                        zip_local_file_header_and_data_size_in_bytes +=
                            zip_local_file_header.compressed_size;

                        println!("Missing Data Descriptor. Calculating compressedSize and uncompressedSize");
                        log_string = format!(
                            "{:-3}{:8}{:8}{:8}{:8} {}::Deflate Calc",
                            zip_local_file_headers.len(),
                            zip_local_file_header.compressed_size,
                            zip_local_file_header.uncompressed_size,
                            zip_local_file_header.extra_field_length,
                            zip_local_file_header_and_data_size_in_bytes,
                            &path
                        );
                    }
                }
            } else {
                binary_reader.seek_relative(zip_local_file_header.compressed_size as i64)?;
            }
        } else if zip_local_file_header.compression_method == 0 {
            // uncompressed data
            let mut crc32 = Crc32::new();
            if zip_local_file_header.fhas_data_descriptor() {
                // Calc and verify the CRC for Data Descriptor case
                let mut running_hash_t: u32 = 0;
                let data_descriptor_signature: [u8; 4] = [0x50, 0x4b, 0x07, 0x08];
                let mut index_into_data_descriptor_signature = 0;

                loop {
                    let current_byte = binary_reader.read_u8()?;
                    if current_byte
                        == data_descriptor_signature[index_into_data_descriptor_signature]
                    {
                        if index_into_data_descriptor_signature == 0 {
                            running_hash_t = crc32.get_running_hash(); // Save away the hash value prior to the signature start
                        }

                        index_into_data_descriptor_signature += 1;
                    } else {
                        index_into_data_descriptor_signature = 0;
                    }

                    // Check if we found a Data Descriptor
                    if index_into_data_descriptor_signature > 3 {
                        let current_position = binary_reader.stream_position()?;
                        if fread_data_descriptor(
                            &mut binary_reader,
                            &mut zip_local_file_header.crc32,
                            &mut zip_local_file_header.compressed_size,
                            &mut zip_local_file_header.uncompressed_size,
                        )? {
                            zip_local_file_header_and_data_size_in_bytes +=
                                zip_local_file_header.compressed_size;
                            log_string = format!(
                                "{:-3}{:8}{:8}{:8}{:8}{}::DD",
                                zip_local_file_headers.len(),
                                zip_local_file_header.compressed_size,
                                zip_local_file_header.uncompressed_size,
                                zip_local_file_header.extra_field_length,
                                zip_local_file_header_and_data_size_in_bytes,
                                &path
                            );

                            crc32.set_running_hash(running_hash_t); // Can't include Data Descriptor Signature in the CRC
                            break;
                        }

                        index_into_data_descriptor_signature = 0;
                        binary_reader.seek(SeekFrom::Start(current_position))?;
                    }

                    crc32.update_crc(current_byte);
                }
            } else
            // No Data Descriptor...use compressed size in local header
            {
                if check_data_crc {
                    // Calc and verify the CRC
                    for _i in 0..zip_local_file_header.compressed_size {
                        crc32.update_crc(binary_reader.read_u8()?);
                    }
                } else {
                    binary_reader.seek(SeekFrom::Current(
                        zip_local_file_header.compressed_size as i64,
                    ))?;
                }
            }

            if check_data_crc && zip_local_file_header.crc32 != crc32.finalize_and_return_crc() {
                println!(
                    "Header CRC: {:8X} != Data CRC: {:8X}...Possible CORRUPT FILE.",
                    zip_local_file_header.local_file_header_signature,
                    crc32.finalize_and_return_crc()
                );
            }
        } else
        // Unsupported compression method
        {
            if check_data_crc {
                println!(
                    "No CRC check...unsupported compreesion type {}",
                    zip_local_file_header.compression_method
                );
            }

            binary_reader.seek(SeekFrom::Current(
                zip_local_file_header.compressed_size as i64,
            ))?;
        }

        println!("{}", log_string);

        for i in 0..NUMBER_OF_SIZE_BUCKETS {
            // track chunks sizes
            if zip_local_file_header_and_data_size_in_bytes
                < zip_file_compressed_size_buckets[i as usize][0]
            {
                zip_file_compressed_size_buckets[i as usize][1] += 1;
                break;
            }
        }
    }

    println!("Found {} Zip Headers\n", zip_local_file_headers.len());
    println!("Looking for Central Directory");

    if signature != zip_structs::ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE {
        println!(
            "+++++No Central Directory Found after Local Zip items++++++ Finding Central Directory"
        );

        binary_reader.seek(SeekFrom::End(-22))?; // Seek 22 bytes back from the end of file
        let zip_end_of_central_directory_record =
            ZipEndOfCentralDirectoryRecord::create_and_load(&mut binary_reader)?;
        if zip_end_of_central_directory_record.end_of_central_dir_signature
            != zip_structs::ZIP_END_OF_CENTRAL_DIRECTORY_RECORD_SIGNATURE
        {
            return Err(anyhow::Error::msg(
                "Could not find central directory End Record",
            ));
        }

        // Use central directory End Record to move to the start of the central directory file headers
        binary_reader.seek(SeekFrom::Start(
            zip_end_of_central_directory_record
                .offset_of_start_of_central_directory_with_respect_to_the_starting_disk_number
                as u64,
        ))?;
    }

    let mut zip_central_directory_file_headers: Vec<ZipCentralDirectoryFileHeader> = Vec::new();
    let mut zip_central_directory_header_paths: Vec<String> = Vec::new();

    loop {
        // Are the enough bytes for another header?
        if binary_reader.stream_position()?
            + zip_structs::ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIZE_IN_BYTES as u64
            > file_length
        {
            if zip_central_directory_file_headers.len() == 0 {
                return Err(anyhow::Error::msg("File Looks truncated, expected Zip Central Directory File Header but stream contains too few bytes"));
            }
            break;
        }

        let mut zip_central_directory_file_header =
            ZipCentralDirectoryFileHeader::create_and_load(&mut binary_reader)?;

        if zip_central_directory_file_header.central_file_header_signature
            != zip_structs::ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE
        {
            binary_reader.seek_relative(
                -(zip_structs::ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIZE_IN_BYTES as i64),
            )?;
            break;
        }

        zip_central_directory_file_headers.push(zip_central_directory_file_header.clone()); // save this zipCentralHeader for later compare with local header

        let mut path_buf = Vec::<u8>::new();
        path_buf.resize(
            zip_central_directory_file_header.file_name_length as usize,
            0,
        );
        binary_reader.read_exact(&mut path_buf)?;
        let path = String::from_utf8(path_buf)?;

        if zip_central_directory_file_headers.len() == 1 {
            println!("Found Zip Central Directory...Dumping Central Directory Table\n");
            println!(
                "{:-3}{:8}{:8}{:8} {:8} Path",
                "", "CSize", "UCSize", "XSize", "CRC"
            );
        }

        let mut log_string = format!(
            "{:-3}{:8}{:8}{:8} {:8X} {}",
            zip_central_directory_file_headers.len(),
            zip_central_directory_file_header.compressed_size,
            zip_central_directory_file_header.uncompressed_size,
            zip_central_directory_file_header.extra_field_length,
            zip_central_directory_file_header.crc32,
            &path
        );

        zip_central_directory_header_paths.push(path.clone()); // save the file name for compare with local header

        // Extra field
        let pos_central_directory_extra_field_max = binary_reader.stream_position()?
            + zip_central_directory_file_header.extra_field_length as u64;

        while binary_reader.stream_position()? < pos_central_directory_extra_field_max {
            // Expect a ZipExtendedInformationHeader
            let zip_extended_information_header =
                ZipExtendedInformationHeader::create_and_load(&mut binary_reader)?;

            // Do we recognize the type?
            if zip_extended_information_header.header_id
                == zip_structs::ZIP64_EXTENDED_INFORMATION_TYPE_TAG
            {
                // If the extra block size is not large enough to accommodate a
                // Zip64ExtendedInformation, bail.
                // Load the Zip64ExtendedInformation..this will consume DataSize bytes even if there is an error
                let zip64_extended_information = Zip64ExtendedInformation::create_and_load(
                    &mut binary_reader,
                    false,
                    zip_extended_information_header.data_size as u32,
                    zip_central_directory_file_header.uncompressed_size as u32,
                    zip_central_directory_file_header.compressed_size as u32,
                    zip_central_directory_file_header.relative_offset_of_local_header as u32,
                    zip_central_directory_file_header.disk_number_start as u16,
                )?;

                zip_central_directory_file_header.uncompressed_size =
                    zip64_extended_information.size_original;
                zip_central_directory_file_header.compressed_size =
                    zip64_extended_information.size_compressed;
                zip_central_directory_file_header.relative_offset_of_local_header =
                    zip64_extended_information.relative_header_offset;
                zip_central_directory_file_header.disk_number_start =
                    zip64_extended_information.disk_start_number;
                log_string = format!(
                    "{:-3}{:8}{:8}{:8} {:8X} {}::Zip64",
                    zip_central_directory_file_headers.len(),
                    zip_central_directory_file_header.compressed_size,
                    zip_central_directory_file_header.uncompressed_size,
                    zip_central_directory_file_header.extra_field_length,
                    zip_central_directory_file_header.crc32,
                    &path
                );

                // No need to skip forward as ZipExtendedInformationHeader.DataSize bytes were consumed by FLoad above
            } else {
                // Just skip over it
                binary_reader.seek_relative(zip_extended_information_header.data_size as i64)?;
            }
        }

        println!("{}", log_string);

        // File Comment
        binary_reader
            .seek_relative(zip_central_directory_file_header.file_comment_length as i64)?;
    }

    println!(
        "Found {} Zip Central Directory Headers\n",
        zip_central_directory_file_headers.len()
    );

    signature = binary_reader.read_u32::<LittleEndian>()?;
    if signature != zip_structs::ZIP_END_OF_CENTRAL_DIRECTORY_RECORD_SIGNATURE
        && signature != zip_structs::ZIP64_END_OF_CENTRAL_DIRECTORY_RECORD_SIGNATURE
    {
        return Err(anyhow::Error::msg(
            "End of Central Directory Signature missing at end of chain of central headers",
        ));
    }

    if zip_local_file_headers.len() != zip_central_directory_file_headers.len() {
        println!("Central Directory and Local Header table contain different number of elements. Attempting diff anyway.");
        is_file_corrupt = true;
    }

    println!("\nDiffing Central Directory and Local Header table");

    let izh_mac = std::cmp::min(
        zip_local_file_headers.len(),
        zip_central_directory_file_headers.len(),
    );
    for izh in 0..izh_mac {
        let zip_local_file_header = zip_local_file_headers.get(izh).unwrap();
        let zip_central_directory_file_header =
            zip_central_directory_file_headers.get(izh).unwrap();
        let h_num = izh + 1;

        if zip_local_file_header.version_needed_to_extract
            != zip_central_directory_file_header.version_needed_to_extract
        {
            println!(
                "{}: LH VersionNeededToExtract {} <> CD VersionNeededToExtract {}",
                h_num,
                zip_local_file_header.version_needed_to_extract,
                zip_central_directory_file_header.version_needed_to_extract
            );
            is_file_corrupt = true;
        }
        if zip_local_file_header.general_purpose_bit_flag
            != zip_central_directory_file_header.general_purpose_bit_flag
        {
            println!(
                "{}: LH GeneralPurposeBitFlag {} <> CD GeneralPurposeBitFlag {}",
                h_num,
                zip_local_file_header.general_purpose_bit_flag,
                zip_central_directory_file_header.general_purpose_bit_flag
            );
        }
        if zip_local_file_header.compression_method
            != zip_central_directory_file_header.compression_method
        {
            println!(
                "{}: LH CompressionMethod {} <> CD CompressionMethod {}",
                h_num,
                zip_local_file_header.compression_method,
                zip_central_directory_file_header.compression_method
            );
            is_file_corrupt = true;
        }
        if zip_local_file_header.last_mod_file_time
            != zip_central_directory_file_header.last_mod_file_time
        {
            println!(
                "{}: LH LastModFileTime {} <> CD LastModFileTime {}",
                h_num,
                zip_local_file_header.last_mod_file_time,
                zip_central_directory_file_header.last_mod_file_time
            );
            is_file_corrupt = true;
        }
        if zip_local_file_header.last_mod_file_date
            != zip_central_directory_file_header.last_mod_file_date
        {
            println!(
                "{}: LH LastModFileDate {} <> CD LastModFileDate {}",
                h_num,
                zip_local_file_header.last_mod_file_date,
                zip_central_directory_file_header.last_mod_file_date
            );
            is_file_corrupt = true;
        }
        if zip_local_file_header.crc32 != zip_central_directory_file_header.crc32 {
            println!(
                "{}: LH Crc32 {} <> CD Crc32 {}",
                h_num, zip_local_file_header.crc32, zip_central_directory_file_header.crc32
            );
            is_file_corrupt = true;
        }
        if zip_local_file_header.compressed_size
            != zip_central_directory_file_header.compressed_size
        {
            println!(
                "{}: LH CompressedSize {} <> CD CompressedSize {}",
                h_num,
                zip_local_file_header.compressed_size,
                zip_central_directory_file_header.compressed_size
            );
            is_file_corrupt = true;
        }
        if zip_local_file_header.uncompressed_size
            != zip_central_directory_file_header.uncompressed_size
        {
            println!(
                "{}: LH UncompressedSize {} <> CD UncompressedSize {}",
                h_num,
                zip_local_file_header.uncompressed_size,
                zip_central_directory_file_header.uncompressed_size
            );
            is_file_corrupt = true;
        }
        if zip_local_file_header.file_name_length
            != zip_central_directory_file_header.file_name_length
        {
            println!(
                "{}: LH FileNameLength {} <> CD FileNameLength {}",
                h_num,
                zip_local_file_header.file_name_length,
                zip_central_directory_file_header.file_name_length
            );
            is_file_corrupt = true;
        }
        if zip_local_file_header.extra_field_length
            != zip_central_directory_file_header.extra_field_length
        {
            println!(
                "{}: LH ExtraFieldLength {} <> CD ExtraFieldLength {} (expected in metro files)",
                h_num,
                zip_local_file_header.extra_field_length,
                zip_central_directory_file_header.extra_field_length
            );
        }

        let zip_local_file_header_path = zip_local_file_header_paths.get(izh).unwrap();
        let zip_central_directory_header_path =
            zip_central_directory_header_paths.get(izh).unwrap();
        if zip_local_file_header_path != zip_central_directory_header_path {
            println!(
                "{}: LH FileHeaderPath {} <> CD FileHeaderPath {}",
                h_num, zip_local_file_header_path, zip_central_directory_header_path
            );
            is_file_corrupt = true;
        }
    }

    if is_file_corrupt {
        println!(
            "ERROR: most likely CORRUPT. Inline Zip Headers do not match Zip Central Directory.\n"
        );
    } else {
        println!("Zip file read successful! File looks ok.\n");
    }

    println!("Historgram of Chunks Sizes:");
    let mut cb_last: u64 = 0;
    for i in 0..NUMBER_OF_SIZE_BUCKETS {
        println!(
            "There were {} between {} and {}",
            zip_file_compressed_size_buckets[i as usize][1],
            cb_last,
            zip_file_compressed_size_buckets[i as usize][0]
        );
        cb_last = zip_file_compressed_size_buckets[i as usize][0];
    }
    Ok(())
}

fn show_help() {
    println!("Usage: zipcheck.exe [-? | -v -x -c] <filename>");
    println!("Read <filename> validating the iznline and central directory zip headers.");
    println!();
    println!("Flags:");
    println!("\t-?\t Print this help message");
    println!("\t-v\t Verbose mode..Compressed blocks information will be output");
    println!("\t-x\t Verbose Ex mode..Compressed blocks information will be output included Deflate block info.");
    println!(
        "\t-c\t Perform CRC validation. Data is uncompressed and CRC is calculated and verified."
    );
    println!();
}

fn main() {
    match main_with_result() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error: {0:?}", e);
        }
    }
}
