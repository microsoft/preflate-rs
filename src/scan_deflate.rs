use std::io::Cursor;

use crate::{
    idat_parse::{parse_idat, IdatContents},
    preflate_container::{decompress_deflate_stream, DecompressResult},
};

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Read, Seek, SeekFrom};

use anyhow::Result;

/// The minimum size of a block that is considered for splitting into chunks
const MIN_BLOCKSIZE: usize = 1024;

#[derive(Debug)]
pub enum BlockChunk {
    /// just a bunch of normal bytes that are copied to the output
    Literal(usize),

    /// Deflate stream
    DeflateStream(DecompressResult),

    /// PNG IDAT, which is a concatenated Zlib stream of IDAT chunks. This
    /// is special since the Deflate stream is split into IDAT chunks.
    IDATDeflate(IdatContents, DecompressResult),
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
enum Signature {
    Zlib(u8),
    ZipLocalFileHeader,
    Gzip,
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
            _ => continue,
        };

        *index = i;
        return Some(s);
    }
    None
}

/// Scans for deflate streams in a zlib compressed file, decompresses the streams and
/// PNG IDAT chunks, and returns the locations of the streams.
pub fn split_into_deflate_streams(
    src: &[u8],
    locations_found: &mut Vec<BlockChunk>,
    loglevel: u32,
) {
    let mut index: usize = 0;
    let mut prev_index = 0;
    while let Some(signature) = next_signature(src, &mut index) {
        match signature {
            Signature::Zlib(_) => {
                if let Ok(res) = decompress_deflate_stream(&src[index + 2..], true, loglevel) {
                    if res.plain_text.len() > MIN_BLOCKSIZE {
                        index += 2;

                        locations_found.push(BlockChunk::Literal(index - prev_index));

                        index += res.compressed_size;

                        locations_found.push(BlockChunk::DeflateStream(res));

                        prev_index = index;
                        continue;
                    }
                }
            }

            Signature::Gzip => {
                let mut cursor = Cursor::new(&src[index..]);
                if skip_gzip_header(&mut cursor).is_ok() {
                    let start = index + cursor.position() as usize;
                    if let Ok(res) = decompress_deflate_stream(&src[start..], true, loglevel) {
                        if res.plain_text.len() > MIN_BLOCKSIZE {
                            locations_found.push(BlockChunk::Literal(start - prev_index));

                            index = start + res.compressed_size;
                            prev_index = index;

                            locations_found.push(BlockChunk::DeflateStream(res));

                            continue;
                        }
                    }
                }
            }

            Signature::ZipLocalFileHeader => {
                if let Ok((header_size, res)) = parse_zip_stream(&src[index..]) {
                    if res.plain_text.len() > MIN_BLOCKSIZE {
                        locations_found.push(BlockChunk::Literal(index - prev_index + header_size));

                        index += header_size + res.compressed_size;
                        prev_index = index;

                        locations_found.push(BlockChunk::DeflateStream(res));

                        continue;
                    }
                }
            }

            Signature::IDAT => {
                if index >= 4 {
                    // idat has the length first, then the "IDAT", so we need to look back 4 bytes
                    // if we find and IDAT
                    let real_start = index - 4;
                    if let Ok((r, payload)) = parse_idat(&src[real_start..], 0) {
                        if let Ok(res) = decompress_deflate_stream(&payload, true, loglevel) {
                            let length = r.total_chunk_length;
                            if length > MIN_BLOCKSIZE {
                                locations_found.push(BlockChunk::Literal(real_start - prev_index));

                                locations_found.push(BlockChunk::IDATDeflate(r, res));

                                index = real_start + length;
                                prev_index = index;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        // wasn't able to match any of the known signatures, so skip the current byte
        index += 1;
    }

    // add the last literal block at the end
    if prev_index < src.len() {
        locations_found.push(BlockChunk::Literal(src.len() - prev_index));
    }
}

fn skip_gzip_header<R: Read>(reader: &mut R) -> Result<()> {
    let mut buffer = [0; 10];
    reader.read_exact(&mut buffer)?; // Read past the fixed 10-byte GZIP header

    if buffer[2] != 8 {
        return Err(anyhow::Error::msg("Unsupported compression method"));
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

#[test]
fn parse_png() {
    let f = crate::process::read_file("treegdi.png");

    let mut locations_found = Vec::new();
    split_into_deflate_streams(&f, &mut locations_found, 1);

    println!("locations found: {:?}", locations_found);
}

#[test]
fn parse_gz() {
    let f = crate::process::read_file("sample1.bin.gz");

    let mut locations_found = Vec::new();
    split_into_deflate_streams(&f, &mut locations_found, 1);

    println!("locations found: {:?}", locations_found);

    assert_eq!(locations_found.len(), 3);

    // 10 byte header
    assert!(match locations_found[0] {
        BlockChunk::Literal(10) => true,
        _ => false,
    });

    // Deflate stream
    assert!(match locations_found[1] {
        BlockChunk::DeflateStream(_) => true,
        _ => false,
    });

    // 8 byte footer
    assert!(match locations_found[2] {
        BlockChunk::Literal(8) => true,
        _ => false,
    });
}

#[test]
fn parse_docx() {
    let f = crate::process::read_file("file-sample_1MB.docx");

    let mut locations_found = Vec::new();
    split_into_deflate_streams(&f, &mut locations_found, 1);

    for x in locations_found {
        match x {
            BlockChunk::Literal(l) => {
                println!("Literal: {}", l);
            }
            BlockChunk::DeflateStream(d) => {
                println!("Deflate: {:?}", d.compressed_size);
            }
            BlockChunk::IDATDeflate(i, d) => {
                println!("IDAT: {:?} {:?}", i, d.compressed_size);
            }
        }
    }

    //assert_eq!(locations_found.len(), 1);
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
    pub fn create_and_load<R: Read>(binary_reader: &mut R) -> anyhow::Result<Self> {
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
fn parse_zip_stream(contents: &[u8]) -> anyhow::Result<(usize, DecompressResult)> {
    let mut binary_reader = Cursor::new(&contents);

    // read the signature
    let zip_local_file_header = ZipLocalFileHeader::create_and_load(&mut binary_reader)?;
    let signature = zip_local_file_header.local_file_header_signature;
    if signature != ZIP_LOCAL_FILE_HEADER_SIGNATURE {
        return Err(anyhow::Error::msg("No local header"));
    }

    // read extended information
    let mut file_name_buf = vec![0; zip_local_file_header.file_name_length as usize];
    binary_reader.read_exact(&mut file_name_buf)?;
    let _path = String::from_utf8(file_name_buf)?;

    // Skip Extra field
    binary_reader.seek(SeekFrom::Current(
        zip_local_file_header.extra_field_length as i64,
    ))?;

    // Handle the compressed DATA. Currently only Deflate (8) and uncompressed (0) are supported.
    if zip_local_file_header.compression_method == 8 {
        let deflate_start_position = binary_reader.stream_position()? as usize;

        if let Ok(res) = decompress_deflate_stream(&contents[deflate_start_position..], true, 1) {
            return Ok((deflate_start_position, res));
        }
    }

    Err(anyhow::Error::msg("No deflate stream found"))
}
