use std::io::Cursor;

use crate::{decompress_deflate_stream, DecompressResult};

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Read, Seek, SeekFrom};

#[derive(Hash, Eq, PartialEq, Copy, Clone, Debug)]
pub enum Signature {
    Zlib(u8),
    ZipLocalFileHeader,
    Gzip,
}

fn next_signature(src: &[u8], index: &mut usize) -> Option<Signature> {
    if src.len() == 0 {
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
            _ => continue,
        };

        *index = i;
        return Some(s);
    }
    None
}

#[derive(Debug)]
pub struct DeflateStreamLocation {
    pub signature: Signature,
    pub start: usize,
    pub data: DecompressResult,
}

pub fn search_for_deflate_streams(src: &[u8], locations_found: &mut Vec<DeflateStreamLocation>) {
    let mut index: usize = 0;
    while let Some(signature) = next_signature(src, &mut index) {
        match signature {
            Signature::Zlib(_) | Signature::Gzip => {
                if let Ok(res) = decompress_deflate_stream(&src[index + 2..], true) {
                    index += 2;
                    let start = index;
                    index += res.compressed_size as usize;

                    locations_found.push(DeflateStreamLocation {
                        signature,
                        start,
                        data: res,
                    });
                } else {
                    index += 2;
                }
            }

            Signature::ZipLocalFileHeader => {
                if find_zip_stream(src, &mut index, locations_found).is_err() {
                    index += 2;
                }
            }
        }
    }
}

const ZIP_LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x04034b50;

#[derive(Default)]
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

fn find_zip_stream(
    src: &[u8],
    index: &mut usize,
    locations_found: &mut Vec<DeflateStreamLocation>,
) -> anyhow::Result<()> {
    let contents = &src[*index..];

    let mut binary_reader = Cursor::new(&contents);

    // read the signature
    let zip_local_file_header = ZipLocalFileHeader::create_and_load(&mut binary_reader)?;
    let signature = zip_local_file_header.local_file_header_signature;
    if signature != ZIP_LOCAL_FILE_HEADER_SIGNATURE {
        return Err(anyhow::Error::msg("No local header"));
    }

    // read extended information
    let mut file_name_buf = Vec::<u8>::new();
    file_name_buf.resize(zip_local_file_header.file_name_length as usize, 0);
    binary_reader.read_exact(&mut file_name_buf)?;
    let _path = String::from_utf8(file_name_buf)?;

    // Skip Extra field
    binary_reader.seek(SeekFrom::Current(
        zip_local_file_header.extra_field_length as i64,
    ))?;

    // Handle the compressed DATA. Currently only Deflate (8) and uncompressed (0) are supported.
    if zip_local_file_header.compression_method == 8 {
        let deflate_start_position = binary_reader.stream_position()? as usize;

        if let Ok(res) = decompress_deflate_stream(&src[*index + deflate_start_position..], true) {
            *index += deflate_start_position;
            let start = *index;
            *index += res.compressed_size as usize;

            locations_found.push(DeflateStreamLocation {
                signature: Signature::ZipLocalFileHeader,
                start,
                data: res,
            });
            return Ok(());
        }
    }

    Err(anyhow::Error::msg("No deflate stream found"))
}
