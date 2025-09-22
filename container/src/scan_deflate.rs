use std::{io::Cursor, ops::Range};

use crate::{
    PreflateContainerConfig,
    idat_parse::{IdatContents, PngHeader, parse_idat, parse_ihdr},
};

use lepton_jpeg::{DEFAULT_THREAD_POOL, EnabledFeatures};
use preflate_rs::{
    ExitCode, PlainText, PreflateConfig, PreflateStreamChunkResult, PreflateStreamProcessor,
    TokenPredictorParameters, err_exit_code,
};

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Read, Seek};

use preflate_rs::Result;

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

    /// JPEG stream, which is a Lepton JPEG stream.
    JPEGLepton(Vec<u8>),
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
    /// JPEG start marker
    JPEG,
}

fn next_signature(src: &[u8], index: &mut usize) -> Option<Signature> {
    if src.is_empty() {
        return None;
    }

    for i in *index..src.len() - 1 {
        let sig = u16::from_be_bytes([src[i], src[i + 1]]);

        // 1. CMF (Compression Method and Flags) — 1st byte
        // This byte is split into two parts:
        //  Bits 0–3 (CM): Compression method (8 = DEFLATE)
        //  Bits 4–7 (CINFO): Compression info
        //   Indicates window size. For DEFLATE, the value CINFO is such that window size = 2^(CINFO + 8)
        //   Cannot be larger than 7, since that would be larger than 32K window size.
        // 2. FLG (Flags) — 2nd byte
        //  This byte also contains several fields:
        //   Bits 0–4 (FCHECK): Check bits for CMF and FLG (to make header divisible by 31)
        //   Bit 5 (FDICT): Preset dictionary flag (1 = dictionary present, should be 0)
        //   Bits 6–7 (FLEVEL): Compression level indicator (informational)

        if sig & 0x8f20 == 0x0800 {
            // possible zlib signature, check to see if it is % 31
            if sig % 31 == 0 {
                *index = i;
                return Some(Signature::Zlib(0));
            }
        }

        let s = match sig {
            0x504B => Signature::ZipLocalFileHeader,
            0x1F8B => Signature::Gzip,
            0x4944 => Signature::IDAT,
            0x4948 => Signature::IHDR,
            0xFFD8 => Signature::JPEG,
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
pub fn find_compressable_stream(
    src: &[u8],
    prev_ihdr: &mut Option<PngHeader>,
    input_complete: bool,
    config: &PreflateContainerConfig,
) -> FindStreamResult {
    let mut index: usize = 0;
    while let Some(signature) = next_signature(src, &mut index) {
        match signature {
            Signature::Zlib(_) => {
                let mut state = PreflateStreamProcessor::new(&config.preflate_config());

                if let Ok(res) = state.decompress(&src[index + 2..]) {
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

                    let mut state = PreflateStreamProcessor::new(&config.preflate_config());
                    if let Ok(res) = state.decompress(&src[start..]) {
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
                    parse_zip_stream(&src[index..], &config.preflate_config())
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
                            log::debug!("IHDR: {:?}", ihdr);
                            *prev_ihdr = Some(ihdr);
                        }
                        Err(e) => {
                            if e.exit_code() == ExitCode::ShortRead && !input_complete {
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
                    match parse_idat(*prev_ihdr, &src[real_start..]) {
                        Ok((idat_contents, payload)) => {
                            *prev_ihdr = None;
                            let mut state = PreflateStreamProcessor::new(&config.preflate_config());

                            if let Ok(res) = state.decompress(&payload) {
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
                            if e.exit_code() == ExitCode::ShortRead && !input_complete {
                                // we don't have the whole IDAT chunk yet, so tell the caller they need to extend the buffer
                                return FindStreamResult::ShortRead;
                            }
                        }
                    }
                }
            }
            Signature::JPEG => {
                let mut output = Vec::new();

                // only required feature is that we can stop reading at the EOI marker
                let features = EnabledFeatures {
                    stop_reading_at_eoi: true,
                    ..EnabledFeatures::compat_lepton_vector_write()
                };

                let mut input = Cursor::new(&src[index..]);
                match lepton_jpeg::encode_lepton(
                    &mut input,
                    &mut Cursor::new(&mut output),
                    &features,
                    &DEFAULT_THREAD_POOL,
                ) {
                    Ok(_m) => {
                        if config.validate_compression {
                            // verify that the JPEG stream can be decoded
                            let mut validate = Vec::with_capacity(input.position() as usize);
                            if let Err(e) = lepton_jpeg::decode_lepton(
                                &mut Cursor::new(&output),
                                &mut validate,
                                &EnabledFeatures::compat_lepton_vector_read(),
                                &DEFAULT_THREAD_POOL,
                            ) {
                                log::warn!("Failed to decode JPEG, skipping: {}", e);
                                index += input.position() as usize;
                                continue;
                            }

                            if src[index..index + input.position() as usize] != validate {
                                log::warn!("JPEG validation failed, skipping, data does not match");
                                index += input.position() as usize;
                                continue;
                            }
                        }

                        // successfully encoded the JPEG stream, return the found stream
                        return FindStreamResult::Found(
                            index..index + input.position() as usize,
                            FoundStream {
                                chunk_type: FoundStreamType::JPEGLepton(output),
                                corrections: Vec::new(),
                            },
                        );
                    }
                    Err(e) => {
                        if e.exit_code() == lepton_jpeg::ExitCode::ShortRead && !input_complete {
                            // we don't have the whole JPEG stream yet, so tell the caller they need to extend the buffer
                            return FindStreamResult::ShortRead;
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
    config: &PreflateConfig,
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
    let mut extra_field_buf = vec![0; zip_local_file_header.extra_field_length.into()];
    binary_reader.read_exact(&mut extra_field_buf)?;

    // Handle the compressed DATA. Currently only Deflate (8) and uncompressed (0) are supported.
    if zip_local_file_header.compression_method == 8 {
        let deflate_start_position = binary_reader.stream_position()? as usize;

        let mut state = PreflateStreamProcessor::new(config);

        if let Ok(res) = state.decompress(&contents[deflate_start_position..]) {
            return Ok((deflate_start_position, res, state));
        }
    }

    err_exit_code(ExitCode::InvalidDeflate, "No deflate stream found")
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkTypes {
    DeflateStream,
    DeflateStreamContinue,
    IDATDeflate,
    JPEGLepton,
}

#[cfg(test)]
fn find_streams(f: &[u8], chunk_size_limit: usize) -> Vec<(Range<usize>, ChunkTypes)> {
    let mut offset: usize = 0;
    let maxlen = f.len();
    let mut locations_found = Vec::new();
    while let FindStreamResult::Found(loc, res) = find_compressable_stream(
        &f[offset..maxlen.min(offset.saturating_add(chunk_size_limit))],
        &mut None,
        true,
        &PreflateContainerConfig::default(),
    ) {
        let r = offset + loc.start..offset + loc.end;

        match res.chunk_type {
            FoundStreamType::DeflateStream(_, mut state) => {
                println!(
                    "Deflate stream at {:?}",
                    offset + loc.start..offset + loc.end
                );

                let start = offset + loc.start;

                state.shrink_to_dictionary();

                // continue decompressing the compressed stream until we are done
                offset += loc.end;
                locations_found.push((start..offset, ChunkTypes::DeflateStream));

                while !state.is_done() {
                    let res = state.decompress(&f[offset..]).unwrap();
                    println!("continue at {}..{}", offset, offset + res.compressed_size);

                    locations_found.push((
                        offset..offset + res.compressed_size,
                        ChunkTypes::DeflateStreamContinue,
                    ));

                    offset += res.compressed_size;

                    state.shrink_to_dictionary();
                }
            }
            FoundStreamType::IDATDeflate(_, idat, _) => {
                println!("IDAT stream at {:?} with chunks: {:?}", r, idat.chunk_sizes);
                locations_found.push((r, ChunkTypes::IDATDeflate));
                offset += loc.end;
            }
            FoundStreamType::JPEGLepton(_) => {
                println!("JPEG stream at {:?}", r);
                locations_found.push((r, ChunkTypes::JPEGLepton));
                offset += loc.end;
            }
        }
    }

    locations_found
}

/// tests with a PDF that has some embedded JPEG images and zlib deflate streams.
#[test]
fn parse_pdf_with_jpeg() {
    let r = find_streams(&crate::utils::read_file("embedded-images.pdf"), usize::MAX);

    use ChunkTypes::*;

    assert_eq!(
        r,
        [
            (1324..3485, DeflateStream),
            (7291..16098, JPEGLepton),
            (16317..22841, JPEGLepton),
            (23060..31468, JPEGLepton),
            (32970..33566, DeflateStream),
            (33919..34492, DeflateStream),
            (54130..99878, DeflateStream),
            (99973..135119, DeflateStream),
            (135214..165568, DeflateStream),
        ]
    );
}

/// parses zip file with limit on chunk size, which should mean that we get an inital deflate stream
/// and then a continuation stream for the rest of the data.
#[test]
fn parse_zip() {
    let r = find_streams(&crate::utils::read_file("pptxplaintext.zip"), 128_000);

    use ChunkTypes::*;
    assert_eq!(
        r,
        [
            (79..126087, DeflateStream),
            (126087..279012, DeflateStreamContinue)
        ]
    );
}

/// should have a single IDAT stream
#[test]
fn parse_png() {
    let f = crate::utils::read_file("treegdi.png");

    let r = find_streams(&f, usize::MAX);

    use ChunkTypes::*;
    assert_eq!(r, [(83..171252, IDATDeflate)]);
}

/// parses a gzipped file, which should have a single deflate stream
#[test]
fn parse_gz() {
    let f = crate::utils::read_file("sample1.bin.gz");

    let r = find_streams(&f, usize::MAX);

    // gz has 10 byte header, so first byte is at 10

    use ChunkTypes::*;
    assert_eq!(r, [(10..263964, DeflateStream)]);
}

/// parses DOCX file that has multiple deflate streams
#[test]
fn parse_docx() {
    let f = crate::utils::read_file("file-sample_1MB.docx");

    let r = find_streams(&f, usize::MAX);

    use ChunkTypes::*;
    assert_eq!(
        r,
        [
            (581..883, DeflateStream),
            (947..1297, DeflateStream),
            (1361..2171, DeflateStream),
            (2239..1018008, DeflateStream),
            (1018076..1018905, DeflateStream),
            (1018966..1020070, DeflateStream),
            (1020133..1024933, DeflateStream),
            (1025579..1025926, DeflateStream)
        ]
    );
}
