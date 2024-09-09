use byteorder::ReadBytesExt;
use std::io::{Read, Write};

use crate::{
    idat_parse::{recreate_idat, IdatContents},
    preflate_error::PreflateError,
    recompress_deflate_stream,
    scan_deflate::{split_into_deflate_streams, BlockChunk},
};

const COMPRESSED_WRAPPER_VERSION_1: u8 = 1;

/// literal chunks are just copied to the output
const LITERAL_CHUNK: u8 = 0;

/// zlib compressed chunks are zlib compressed
const DEFLATE_STREAM: u8 = 1;

/// PNG chunks are IDAT chunks that are zlib compressed
const PNG_COMPRESSED: u8 = 2;

pub fn write_varint(destination: &mut impl Write, value: u32) -> std::io::Result<()> {
    let mut value = value;
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        destination.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }

    Ok(())
}

pub fn read_varint(source: &mut impl Read) -> std::io::Result<u32> {
    let mut result = 0;
    let mut shift = 0;
    loop {
        let mut byte = [0u8; 1];
        source.read_exact(&mut byte)?;
        let byte = byte[0];
        result |= ((byte & 0x7F) as u32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok(result)
}

#[test]
fn test_variant_roundtrip() {
    let values = [
        0, 1, 127, 128, 255, 256, 16383, 16384, 2097151, 2097152, 268435455, 268435456, 4294967295,
    ];

    let mut buffer = Vec::new();
    for &v in values.iter() {
        write_varint(&mut buffer, v).unwrap();
    }

    let mut buffer = &buffer[..];

    for &v in values.iter() {
        assert_eq!(v, read_varint(&mut buffer).unwrap());
    }
}

fn write_chunk_block(
    block: BlockChunk,
    literal_data: &[u8],
    destination: &mut impl Write,
) -> std::io::Result<usize> {
    match block {
        BlockChunk::Literal(content_size) => {
            destination.write_all(&[LITERAL_CHUNK])?;
            write_varint(destination, content_size as u32)?;
            destination.write_all(&literal_data[0..content_size])?;

            Ok(content_size)
        }

        BlockChunk::DeflateStream(res) => {
            destination.write_all(&[DEFLATE_STREAM])?;
            write_varint(destination, res.plain_text.len() as u32)?;
            destination.write_all(&res.plain_text)?;
            write_varint(destination, res.prediction_corrections.len() as u32)?;
            destination.write_all(&res.prediction_corrections)?;

            Ok(res.compressed_size)
        }

        BlockChunk::IDATDeflate(idat, res) => {
            destination.write_all(&[PNG_COMPRESSED])?;
            idat.write_to_bytestream(destination)?;
            write_varint(destination, res.plain_text.len() as u32)?;
            destination.write_all(&res.plain_text)?;
            write_varint(destination, res.prediction_corrections.len() as u32)?;
            destination.write_all(&res.prediction_corrections)?;

            Ok(idat.total_chunk_length)
        }
    }
}

fn read_chunk_block(
    source: &mut impl Read,
    destination: &mut impl Write,
) -> std::result::Result<bool, PreflateError> {
    let mut buffer = [0];
    if source.read(&mut buffer)? == 0 {
        return Ok(false);
    }

    match buffer[0] {
        LITERAL_CHUNK => {
            let mut length = read_varint(source)? as usize;
            while length > 0 {
                let mut buffer = [0; 65536];
                let amount_to_read = std::cmp::min(buffer.len(), length) as usize;

                source.read_exact(&mut buffer[0..amount_to_read])?;
                destination.write_all(&buffer[0..amount_to_read])?;

                length -= amount_to_read;
            }
        }
        DEFLATE_STREAM | PNG_COMPRESSED => {
            let idat = if buffer[0] == PNG_COMPRESSED {
                Some(IdatContents::read_from_bytestream(source)?)
            } else {
                None
            };

            let length = read_varint(source)?;
            let mut segment = vec![0; length as usize];
            source.read_exact(&mut segment)?;

            let corrections_length = read_varint(source)?;
            let mut corrections = vec![0; corrections_length as usize];
            source.read_exact(&mut corrections)?;

            let recompressed = recompress_deflate_stream(&segment, &corrections)?;

            if let Some(idat) = idat {
                recreate_idat(&idat, &recompressed[..], destination)
                    .map_err(|_e| PreflateError::InvalidCompressedWrapper)?;
            } else {
                destination.write_all(&recompressed)?;
            }
        }
        _ => return Err(PreflateError::InvalidCompressedWrapper),
    }
    Ok(true)
}

#[test]
fn roundtrip_chunk_block_literal() {
    let mut buffer = Vec::new();

    write_chunk_block(BlockChunk::Literal(5), b"hello", &mut buffer).unwrap();

    let mut read_cursor = std::io::Cursor::new(buffer);
    let mut destination = Vec::new();
    read_chunk_block(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == b"hello");
}

#[test]
fn roundtrip_chunk_block_deflate() {
    let contents = crate::process::read_file("compressed_zlib_level1.deflate");
    let results = crate::decompress_deflate_stream(&contents, true).unwrap();

    let mut buffer = Vec::new();

    write_chunk_block(BlockChunk::DeflateStream(results), &[], &mut buffer).unwrap();

    let mut read_cursor = std::io::Cursor::new(buffer);
    let mut destination = Vec::new();
    read_chunk_block(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == contents);
}

#[test]
fn roundtrip_chunk_block_png() {
    let f = crate::process::read_file("treegdi.png");

    // we know the first IDAT chunk starts at 83 (avoid testing the scan_deflate code in a unit teast)
    let (idat_contents, deflate_stream) = crate::idat_parse::parse_idat(&f[83..], 1).unwrap();
    let results = crate::decompress_deflate_stream(&deflate_stream, true).unwrap();

    let total_chunk_length = idat_contents.total_chunk_length;

    let mut buffer = Vec::new();

    write_chunk_block(
        BlockChunk::IDATDeflate(idat_contents, results),
        &[],
        &mut buffer,
    )
    .unwrap();

    let mut read_cursor = std::io::Cursor::new(buffer);
    let mut destination = Vec::new();
    read_chunk_block(&mut read_cursor, &mut destination).unwrap();

    assert!(destination == &f[83..83 + total_chunk_length]);
}

/// scans for deflate streams in a zlib compressed file, decompresses the streams and
/// returns an uncompressed file that can then be recompressed using a better algorithm.
/// This can then be passed back into recreated_zlib_chunks to recreate the exact original file.
pub fn expand_zlib_chunks(compressed_data: &[u8]) -> std::result::Result<Vec<u8>, PreflateError> {
    let mut locations_found = Vec::new();

    split_into_deflate_streams(compressed_data, &mut locations_found);
    println!("locations found: {:?}", locations_found);

    let mut plain_text = Vec::new();
    plain_text.push(COMPRESSED_WRAPPER_VERSION_1); // version 1 of format. Definitely will improved.

    let mut index = 0;
    for loc in locations_found {
        index += write_chunk_block(loc, &compressed_data[index..], &mut plain_text)?;
    }

    Ok(plain_text)
}

/// takes a binary chunk of data that was created by expand_zlib_chunks and recompresses it back to its
/// original form.
pub fn recreated_zlib_chunks(
    source: &mut impl Read,
    destination: &mut impl Write,
) -> std::result::Result<(), PreflateError> {
    let version = source.read_u8()?;
    if version != COMPRESSED_WRAPPER_VERSION_1 {
        return Err(PreflateError::InvalidCompressedWrapper);
    }

    loop {
        if !read_chunk_block(source, destination)? {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
fn roundtrip_deflate_chunks(filename: &str) {
    let f = crate::process::read_file(filename);

    let expanded = expand_zlib_chunks(&f).unwrap();

    let mut read_cursor = std::io::Cursor::new(expanded);

    let mut destination = Vec::new();
    recreated_zlib_chunks(&mut read_cursor, &mut destination).unwrap();

    assert_eq!(destination.len(), f.len());
    for i in 0..destination.len() {
        assert_eq!(destination[i], f[i], "Mismatch at index {}", i);
    }
    assert!(destination == f);
}

#[test]
fn roundtrip_png_chunks() {
    roundtrip_deflate_chunks("treegdi.png");
}

#[test]
fn roundtrip_zip_chunks() {
    roundtrip_deflate_chunks("samplezip.zip");
}

#[test]
fn roundtrip_gz_chunks() {
    roundtrip_deflate_chunks("sample1.bin.gz");
}

#[test]
fn roundtrip_pdf_chunks() {
    roundtrip_deflate_chunks("starcontrol.samplesave");
}
