use std::{io::Cursor, ops::Range};

use crate::{
    estimator::preflate_parameter_estimator::TokenPredictorParameters,
    idat_parse::{IdatContents, PngHeader, parse_idat, parse_ihdr},
    preflate_error::{ExitCode, err_exit_code},
    preflate_input::PlainText,
    stream_processor::{PreflateStreamChunkResult, PreflateStreamProcessor},
};

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Read, Seek, SeekFrom};

use crate::preflate_error::Result;

/// The minimum size of a block that is considered for splitting into chunks
const MIN_BLOCKSIZE: usize = 1024;

pub struct FoundStream {
    pub chunk_type: FoundStreamType,
    pub corrections: Vec<u8>,
}

pub enum FoundStreamType {
    /// Deflate stream
    DeflateStream(TokenPredictorParameters, PreflateStreamProcessor),

    /// PNG IDAT, which is a concatenated Zlib stream of IDAT chunks. This
    /// is special since the Deflate stream is split into IDAT chunks.
    IDATDeflate(TokenPredictorParameters, IdatContents, PlainText),
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
enum Signature {
    Zlib(u8),
    ZipLocalFileHeader,
    Gzip,
    /// PNG IHDR chunk which contains the width, height of the image and color format of the image.
    /// We keep the parsed data around so that we know the dimensions etc of the IDAT when we find it.
    IHDR,
    /// PNG IDAT, which is a concatenated Zlib stream of IDAT chunks, each of the size given in the Vec.
    IDAT,
}

fn next_signature(src: &[u8], index: &mut usize) -> Option<Signature> {
    if src.is_empty() {
        return None;
    }

    for i in *index..src.len() - 1 {
        let sig = u16::from_le_bytes([src[i], src[i + 1]]);

        let s = match sig {
            0x0178 => Signature::Zlib(0),
            0x5E78 => Signature::Zlib(1),
            0x9C78 => Signature::Zlib(5),
            0xDA78 => Signature::Zlib(8),
            0x4B50 => Signature::ZipLocalFileHeader,
            0x8B1F => Signature::Gzip,
            0x4449 => Signature::IDAT,
            0x4849 => Signature::IHDR,
            _ => continue,
        };

        *index = i;
        return Some(s);
    }
    None
}

pub enum FindStreamResult {
    None,
    Found(Range<usize>, FoundStream),
    ShortRead,
}

/// Scans for deflate streams in a zlib compressed file, decompresses the streams and
/// PNG IDAT chunks, and returns the locations of the streams.
pub fn find_deflate_stream(
    src: &[u8],
    loglevel: u32,
    plain_text_limit: usize,
    prev_ihdr: &mut Option<PngHeader>,
) -> FindStreamResult {
    let mut index: usize = 0;
    while let Some(signature) = next_signature(src, &mut index) {
        match signature {
            Signature::Zlib(_) => {
                let mut state = PreflateStreamProcessor::new(plain_text_limit, true);

                if let Ok(res) = state.decompress(&src[index + 2..], loglevel) {
                    if state.plain_text().len() > MIN_BLOCKSIZE {
                        index += 2;
                        return FindStreamResult::Found(
                            index..index + res.compressed_size,
                            FoundStream {
                                chunk_type: FoundStreamType::DeflateStream(
                                    res.parameters.unwrap(),
                                    state,
                                ),
                                corrections: res.corrections,
                            },
                        );
                    }
                }
            }

            Signature::Gzip => {
                let mut cursor = Cursor::new(&src[index..]);
                if skip_gzip_header(&mut cursor).is_ok() {
                    let start = index + cursor.position() as usize;

                    let mut state = PreflateStreamProcessor::new(plain_text_limit, true);
                    if let Ok(res) = state.decompress(&src[start..], loglevel) {
                        if state.plain_text().len() > MIN_BLOCKSIZE {
                            return FindStreamResult::Found(
                                start..start + res.compressed_size,
                                FoundStream {
                                    chunk_type: FoundStreamType::DeflateStream(
                                        res.parameters.unwrap(),
                                        state,
                                    ),
                                    corrections: res.corrections,
                                },
                            );
                        }
                    }
                }
            }

            Signature::ZipLocalFileHeader => {
                if let Ok((header_size, res, state)) =
                    parse_zip_stream(&src[index..], loglevel, plain_text_limit)
                {
                    if state.plain_text().len() > MIN_BLOCKSIZE {
                        return FindStreamResult::Found(
                            index + header_size..index + header_size + res.compressed_size,
                            FoundStream {
                                chunk_type: FoundStreamType::DeflateStream(
                                    res.parameters.unwrap(),
                                    state,
                                ),
                                corrections: res.corrections,
                            },
                        );
                    }
                }
            }

            Signature::IHDR => {
                if index >= 4 {
                    match parse_ihdr(&src[index - 4..]) {
                        Ok(ihdr) => {
                            println!("IHDR: {:?}", ihdr);
                            *prev_ihdr = Some(ihdr);
                        }
                        Err(e) => {
                            if e.exit_code() == ExitCode::ShortRead {
                                // we don't have the whole IHDR chunk yet, so tell the caller they need to extend the buffer
                                return FindStreamResult::ShortRead;
                            }
                        }
                    }
                }
            }

            Signature::IDAT => {
                if index >= 4 {
                    // idat has the length first, then the "IDAT", so we need to look back 4 bytes
                    // if we find and IDAT
                    let real_start = index - 4;
                    println!("IDat at {}, {:?}", real_start, prev_ihdr);
                    match parse_idat(*prev_ihdr, &src[real_start..], 0) {
                        Ok((idat_contents, payload)) => {
                            *prev_ihdr = None;
                            let mut state = PreflateStreamProcessor::new(plain_text_limit, true);

                            if let Ok(res) = state.decompress(&payload, loglevel) {
                                let length = idat_contents.total_chunk_length;
                                if length > MIN_BLOCKSIZE {
                                    return FindStreamResult::Found(
                                        real_start..real_start + idat_contents.total_chunk_length,
                                        FoundStream {
                                            chunk_type: FoundStreamType::IDATDeflate(
                                                res.parameters.unwrap(),
                                                idat_contents,
                                                state.detach_plain_text(),
                                            ),
                                            corrections: res.corrections,
                                        },
                                    );
                                } else {
                                    // if we couldn't successfully decompress the IDAT, skip the IDAT
                                    // since otherwise we will attempt to decompress it again when we
                                    // hit the Zlib signature and fail a second time.
                                    index = real_start + idat_contents.total_chunk_length;
                                }
                            }
                        }
                        Err(e) => {
                            if e.exit_code() == ExitCode::ShortRead {
                                // we don't have the whole IDAT chunk yet, so tell the caller they need to extend the buffer
                                return FindStreamResult::ShortRead;
                            }
                        }
                    }
                }
            }
        }

        // wasn't able to match any of the known signatures, so skip the current byte
        index += 1;
    }

    FindStreamResult::None
}

fn skip_gzip_header<R: Read>(reader: &mut R) -> Result<()> {
    let mut buffer = [0; 10];
    reader.read_exact(&mut buffer)?; // Read past the fixed 10-byte GZIP header

    if buffer[2] != 8 {
        return err_exit_code(ExitCode::InvalidDeflate, "Unsupported compression method");
    }

    if buffer[3] & 0x04 != 0 {
        // FEXTRA flag is set, read extra data
        let mut extra_len = [0; 2];
        reader.read_exact(&mut extra_len)?;
        let extra_len = u16::from_le_bytes(extra_len);
        let mut extra = vec![0; extra_len as usize];
        reader.read_exact(&mut extra)?;
    }

    if buffer[3] & 0x08 != 0 {
        // FNAME flag is set, read null-terminated file name
        while reader.read_u8()? != 0 {}
    }

    if buffer[3] & 0x10 != 0 {
        // FCOMMENT flag is set, read null-terminated comment
        while reader.read_u8()? != 0 {}
    }

    if buffer[3] & 0x02 != 0 {
        // FHCRC flag is set, read 2-byte CRC16 for header
        let mut crc16 = [0; 2];
        reader.read_exact(&mut crc16)?;
    }

    Ok(())
}

const ZIP_LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x04034b50;

#[derive(Default)]
#[allow(dead_code)]
pub struct ZipLocalFileHeader {
    pub local_file_header_signature: u32,
    pub version_needed_to_extract: u16,
    pub general_purpose_bit_flag: u16,
    pub compression_method: u16,
    pub last_mod_file_time: u16,
    pub last_mod_file_date: u16,
    pub crc32: u32,
    pub compressed_size: u64, // only 4 bytes in the regular header but can be 8 bytes if Zip64
    pub uncompressed_size: u64, // only 4 bytes in the regular header but can be 8 bytes if Zip64
    pub file_name_length: u16,
    pub extra_field_length: u16,
}

impl ZipLocalFileHeader {
    pub fn create_and_load<R: Read>(binary_reader: &mut R) -> Result<Self> {
        let zip_local_file_header = Self {
            local_file_header_signature: binary_reader.read_u32::<LittleEndian>()?,
            version_needed_to_extract: binary_reader.read_u16::<LittleEndian>()?,
            general_purpose_bit_flag: binary_reader.read_u16::<LittleEndian>()?,
            compression_method: binary_reader.read_u16::<LittleEndian>()?,
            last_mod_file_time: binary_reader.read_u16::<LittleEndian>()?,
            last_mod_file_date: binary_reader.read_u16::<LittleEndian>()?,
            crc32: binary_reader.read_u32::<LittleEndian>()?,
            compressed_size: binary_reader.read_u32::<LittleEndian>()? as u64,
            uncompressed_size: binary_reader.read_u32::<LittleEndian>()? as u64,
            file_name_length: binary_reader.read_u16::<LittleEndian>()?,
            extra_field_length: binary_reader.read_u16::<LittleEndian>()?,
        };

        Ok(zip_local_file_header)
    }
}

/// parses the zip stream and returns the size of the header, followed by the decompressed contents
fn parse_zip_stream(
    contents: &[u8],
    loglevel: u32,
    plain_text_limit: usize,
) -> Result<(usize, PreflateStreamChunkResult, PreflateStreamProcessor)> {
    let mut binary_reader = Cursor::new(&contents);

    // read the signature
    let zip_local_file_header = ZipLocalFileHeader::create_and_load(&mut binary_reader)?;
    let signature = zip_local_file_header.local_file_header_signature;
    if signature != ZIP_LOCAL_FILE_HEADER_SIGNATURE {
        return err_exit_code(ExitCode::InvalidDeflate, "No local header");
    }

    // read extended information
    let mut file_name_buf = vec![0; zip_local_file_header.file_name_length as usize];
    binary_reader.read_exact(&mut file_name_buf)?;
    //let _path = String::from_utf8(file_name_buf).map_err( PreflateError)?;

    // Skip Extra field
    binary_reader.seek(SeekFrom::Current(
        zip_local_file_header.extra_field_length as i64,
    ))?;

    // Handle the compressed DATA. Currently only Deflate (8) and uncompressed (0) are supported.
    if zip_local_file_header.compression_method == 8 {
        let deflate_start_position = binary_reader.stream_position()? as usize;

        let mut state = PreflateStreamProcessor::new(plain_text_limit, true);

        if let Ok(res) = state.decompress(&contents[deflate_start_position..], loglevel) {
            return Ok((deflate_start_position, res, state));
        }
    }

    err_exit_code(ExitCode::InvalidDeflate, "No deflate stream found")
}

#[test]
fn parse_png() {
    let f = crate::utils::read_file("treegdi.png");

    let (loc, chunk) = match find_deflate_stream(&f, 1, usize::MAX, &mut None) {
        FindStreamResult::Found(loc, chunk) => (loc, chunk),
        _ => panic!("Expected FoundStream"),
    };

    match chunk.chunk_type {
        FoundStreamType::IDATDeflate(_p, idat, _plain_text) => {
            println!("IDAT chunks: {:?} at {:?}", idat.chunk_sizes, loc);
        }
        _ => panic!("Expected IDAT"),
    }
}

#[test]
fn parse_gz() {
    let f = crate::utils::read_file("sample1.bin.gz");

    let loc = match find_deflate_stream(&f, 1, usize::MAX, &mut None) {
        FindStreamResult::Found(loc, chunk) => (loc, chunk),
        _ => panic!("Expected FoundStream"),
    };

    // 10 byte header + 8 byte footer
    assert_eq!(loc.0, 10..f.len() - 8);

    if !matches!(loc.1.chunk_type, FoundStreamType::DeflateStream(_, _)) {
        panic!("Expected DeflateStream");
    }
}

#[test]
fn parse_docx() {
    let f = crate::utils::read_file("file-sample_1MB.docx");

    let mut offset = 0;
    while let FindStreamResult::Found(loc, res) =
        find_deflate_stream(&f[offset..], 0, usize::MAX, &mut None)
    {
        match res.chunk_type {
            FoundStreamType::DeflateStream(_, _) => {
                println!(
                    "Deflate stream at {:?}",
                    offset + loc.start..offset + loc.end
                );
            }
            _ => panic!("Expected DeflateStream"),
        }
        offset += loc.end;
    }

    //assert_eq!(locations_found.len(), 1);
}

/// parses zip file with limit on the plain_text size and makes sure that what
/// we get back matches the plaintext exactly
#[test]
fn parse_zip() {
    let f = crate::utils::read_file("pptxplaintext.zip");

    let mut plain_text = Vec::new();

    let mut offset = 0;
    while let FindStreamResult::Found(loc, res) =
        find_deflate_stream(&f[offset..], 1, 1 * 1024 * 1024, &mut None)
    {
        match res.chunk_type {
            FoundStreamType::DeflateStream(_, mut state) => {
                println!(
                    "Deflate stream at {:?}",
                    offset + loc.start..offset + loc.end
                );

                plain_text.extend_from_slice(state.plain_text().text());

                state.shrink_to_dictionary();

                // continue decompressing the compressed stream until we are done
                offset += loc.end;
                while !state.is_done() {
                    let res = state.decompress(&f[offset..], 1).unwrap();
                    println!("continue at {}..{}", offset, offset + res.compressed_size);
                    offset += res.compressed_size;

                    plain_text.extend_from_slice(state.plain_text().text());

                    state.shrink_to_dictionary();
                }
            }
            _ => panic!("Expected DeflateStream"),
        }
    }

    crate::utils::assert_eq_array(&plain_text, &crate::utils::read_file("pptxplaintext.bin"));
}
