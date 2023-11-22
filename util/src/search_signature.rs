use std::{
    collections::HashMap,
    io::{Cursor, Read, Seek, SeekFrom, Write},
};

use anyhow;
use preflate_rs::decompress_deflate_stream;

use crate::zip_structs::{
    self, Zip64ExtendedInformation, ZipExtendedInformationHeader, ZipLocalFileHeader,
};

#[derive(Hash, Eq, PartialEq, Copy, Clone, Debug)]
pub enum Signature {
    Zlib(usize),
    ZipLocalFileHeader,
    Gzip,
}

pub struct DeflateStreamLocation {
    pub start: u64,
    pub end: u64,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub zstd: u64,
    pub signature: Signature,
    pub cabac_length: u64,
}

pub fn add_location(
    list: &mut Vec<DeflateStreamLocation>,
    signature: Signature,
    start: u64,
    compressed: &[u8],
) {
    let ret = decompress_deflate_stream(compressed, true);
    if let Err(_e) = ret
    {
        //println!("Error decompressing {:?} {:?} at {}", signature, e, start);
        return;
    }

    if let Ok(r) = ret {
        let mut output = Vec::new();
        let mut encoder = zstd::stream::Encoder::new(&mut output, 9).unwrap();

        encoder.write(&r.plain_text).unwrap();
        encoder.finish().unwrap();

        list.push(DeflateStreamLocation {
            start,
            end: start + r.compressed_processed as u64,
            uncompressed_size: r.plain_text.len() as u64,
            compressed_size: r.compressed_processed as u64,
            signature: signature,
            zstd: output.len() as u64,
            cabac_length: r.cabac_encoded.len() as u64,
        });
    }
}

pub const HASH_TO_SIGNATURE: [([u8; 2], Signature); 6] = [
    ([0x78, 0x01], Signature::Zlib(0)),
    ([0x78, 0x5E], Signature::Zlib(1)),
    ([0x78, 0x9C], Signature::Zlib(5)),
    ([0x78, 0xDA], Signature::Zlib(8)),
    ([0x50, 0x4B], Signature::ZipLocalFileHeader),
    ([0x1f, 0x8b], Signature::Gzip),
];

pub fn search_signature(src: &[u8], index: &mut usize) -> Option<Signature> {
    let signatures: &HashMap<[u8; 2], Signature> = &HASH_TO_SIGNATURE.iter().cloned().collect();

    if src.len() == 0 {
        return None;
    }

    for i in *index..src.len() - 1 {
        let mut signature: [u8; 2] = [0; 2];
        signature[0] = src[i];
        signature[1] = src[i + 1];
        if let Some(s) = signatures.get(&signature) {
            *index = i + 2;
            return Some(*s);
        }
    }
    None
}

pub fn search_for_deflate_streams(src: &[u8], locations_found: &mut Vec<DeflateStreamLocation>) {
    let mut index: usize = 0;
    while let Some(s) = search_signature(src, &mut index) {
        match s {
            Signature::Zlib(_level) => {
                add_location(locations_found, s, index as u64, &src[index..]);
            }
            Signature::Gzip => {
                add_location(locations_found, s, index as u64, &src[index..]);
            }

            Signature::ZipLocalFileHeader => {
                let _r = test_zip_stream(src, &mut index, locations_found);
            }
        }
    }
}

fn test_zip_stream(
    src: &[u8],
    index: &mut usize,
    locations_found: &mut Vec<DeflateStreamLocation>,
) -> anyhow::Result<()> {
    let contents = &src[*index - 2..];

    let mut binary_reader = Cursor::new(&contents);

    // read the signature
    let mut zip_local_file_header = ZipLocalFileHeader::create_and_load(&mut binary_reader)?;
    let signature = zip_local_file_header.local_file_header_signature;
    if signature != zip_structs::ZIP_LOCAL_FILE_HEADER_SIGNATURE {
        return Err(anyhow::Error::msg("No local header"));
    }

    // read extended information
    let mut file_name_buf = Vec::<u8>::new();
    file_name_buf.resize(zip_local_file_header.file_name_length as usize, 0);
    binary_reader.read_exact(&mut file_name_buf)?;
    let _path = String::from_utf8(file_name_buf)?;

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

            // No need to skip forward as ZipExtendedInformationHeader.DataSize bytes were consumed by load above
        } else {
            // Just skip over it
            binary_reader.seek(SeekFrom::Current(
                zip_extended_information_header.data_size as i64,
            ))?;
        }
    }

    // Handle the compressed DATA. Currently only Deflate (8) and uncompressed (0) are supported.
    if zip_local_file_header.compression_method == 8 {
        let deflate_start_position = binary_reader.stream_position()?;

        add_location(
            locations_found,
            Signature::ZipLocalFileHeader,
            *index as u64 + deflate_start_position,
            &contents[deflate_start_position as usize..],
        );

        *index += binary_reader.position() as usize - 2;
    }

    Ok(())
}
