use std::io::{Read, Write};

use crate::preflate_error::Result;

use crate::{
    preflate_container::{read_varint, write_varint},
    preflate_error::{err_exit_code, ExitCode},
};

/// The contents of a PNG IDat stream. These are treated specially since they
/// contain a Zlib stream that is split into multiple chunks and would be
/// treated as corrupt if we just tried to parse it without removing the boundary headers.
#[derive(Debug, PartialEq)]
pub struct IdatContents {
    /// the sizes of the IDAT chunks
    pub chunk_sizes: Vec<u32>,

    /// the zlib header we found
    pub zlib_header: [u8; 2],

    /// the size of all the chunks combined including headers and crc
    pub total_chunk_length: usize,

    /// addler32 appended to the zlib stream
    pub addler32: u32,
}

impl IdatContents {
    pub fn read_from_bytestream(r: &mut impl Read) -> Result<IdatContents> {
        let mut chunk_sizes = Vec::new();

        loop {
            let r = read_varint(r)?;
            if r == 0 {
                break;
            }
            chunk_sizes.push(r);
        }

        let mut zlib_header = [0, 0];
        r.read_exact(&mut zlib_header)?;

        let mut addler32 = [0u8; 4];
        r.read_exact(&mut addler32)?;

        // total chunk size is the sum of all the chunk sizes + 2 bytes for the zlib header + 4 bytes for the addler32
        let total_chunk_length = chunk_sizes.iter().sum::<u32>() + 2 + 4;

        Ok(IdatContents {
            chunk_sizes,
            zlib_header,
            total_chunk_length: total_chunk_length as usize,
            addler32: u32::from_be_bytes(addler32),
        })
    }

    pub fn write_to_bytestream(&self, w: &mut impl std::io::Write) -> std::io::Result<()> {
        for &chunk_size in self.chunk_sizes.iter() {
            write_varint(w, chunk_size)?;
        }
        write_varint(w, 0)?;

        w.write_all(&self.zlib_header)?;

        w.write_all(&self.addler32.to_be_bytes())?;

        Ok(())
    }
}

/// test that we can read and write the serialized info
#[test]
fn test_idat_header_roundtrip() {
    let idat = IdatContents {
        chunk_sizes: vec![1, 2, 30000],
        zlib_header: [4, 5],
        total_chunk_length: 1 + 2 + 30000 + 2 + 4,
        addler32: 0x12345678,
    };

    let mut buffer = Vec::new();
    idat.write_to_bytestream(&mut buffer).unwrap();

    let mut cur = std::io::Cursor::new(&buffer);

    let idat2 = IdatContents::read_from_bytestream(&mut cur).unwrap();

    assert_eq!(idat, idat2);
}

/// parses PNG IDAT chunks starting from the first one and returns the embedded deflate stream and the IDAT chunk sizes
pub fn parse_idat(
    png_idat_stream: &[u8],
    deflate_info_dump_level: u32,
) -> Result<(IdatContents, Vec<u8>)> {
    if png_idat_stream.len() < 12 || &png_idat_stream[4..8] != b"IDAT" {
        return err_exit_code(ExitCode::InvalidIDat, "No IDAT chunk found");
    }

    let mut deflate_stream = Vec::new();

    // track the chunk sizes we've seen
    let mut idat_chunk_sizes = Vec::new();
    let mut pos = 0;

    while pos < png_idat_stream.len() {
        // png chunks start with the length of the chunk
        let chunk_len = u32::from_be_bytes([
            png_idat_stream[pos],
            png_idat_stream[pos + 1],
            png_idat_stream[pos + 2],
            png_idat_stream[pos + 3],
        ]) as usize;

        // now look at the chunk type. We only want IDAT chunks
        // and they have to be consecutive, so stop once we see
        // something weird
        let chunk_type = &png_idat_stream[pos + 4..pos + 8];
        if chunk_type != b"IDAT" || pos + chunk_len + 12 > png_idat_stream.len() {
            break;
        }

        let chunk = &png_idat_stream[pos + 8..pos + chunk_len + 8];
        deflate_stream.extend_from_slice(chunk);

        let mut crc = crc32fast::Hasher::new();
        crc.update(chunk_type);
        crc.update(chunk);

        if crc.finalize()
            != u32::from_be_bytes([
                png_idat_stream[pos + chunk_len + 8],
                png_idat_stream[pos + chunk_len + 9],
                png_idat_stream[pos + chunk_len + 10],
                png_idat_stream[pos + chunk_len + 11],
            ])
        {
            return err_exit_code(ExitCode::InvalidIDat, "CRC mismatch");
        }

        idat_chunk_sizes.push(chunk_len as u32);
        pos += chunk_len + 12;
    }

    if deflate_info_dump_level > 0 {
        println!("IDAT boundaries: {:?}", idat_chunk_sizes);
    }

    if deflate_stream.len() < 3 {
        return err_exit_code(ExitCode::InvalidIDat, "No IDAT data found");
    }

    // remove the zlib header since it can be somewhat arbitary so we store it seperately
    let idat_zlib_header = [deflate_stream[0], deflate_stream[1]];

    let addler32 = u32::from_be_bytes(
        deflate_stream[deflate_stream.len() - 4..]
            .try_into()
            .unwrap(),
    );

    deflate_stream.drain(0..2);
    deflate_stream.drain(deflate_stream.len() - 4..);

    Ok((
        IdatContents {
            chunk_sizes: idat_chunk_sizes,
            zlib_header: idat_zlib_header,
            total_chunk_length: pos,
            addler32,
        },
        deflate_stream,
    ))
}

/// recreates the IDAT chunks from the header and the deflate stream
pub fn recreate_idat(
    idat: &IdatContents,
    deflate_stream: &[u8],
    output: &mut impl Write,
) -> Result<()> {
    // the total length of the chunks is the sum of the chunk sizes + 2 bytes for the zlib header + 4 bytes for the addler32
    if idat.chunk_sizes.iter().sum::<u32>() as usize != deflate_stream.len() + 2 + 4 {
        return err_exit_code(
            ExitCode::InvalidIDat,
            "Chunk sizes do not match deflate stream length",
        );
    }

    let mut index = 0;

    let mut contents = idat.zlib_header.to_vec();
    contents.extend(deflate_stream);
    contents.extend(idat.addler32.to_be_bytes().iter());

    for &chunk_size in idat.chunk_sizes.iter() {
        output.write_all(&chunk_size.to_be_bytes())?;
        output.write_all(b"IDAT")?;

        let content = &contents[index..index + chunk_size as usize];
        output.write_all(content)?;

        let mut crc = crc32fast::Hasher::new();
        crc.update(b"IDAT");
        crc.update(content);

        output.write_all(&crc.finalize().to_be_bytes())?;

        index += chunk_size as usize;
    }

    Ok(())
}

#[test]
fn parse_and_recreate_png() {
    use crate::deflate::deflate_reader::parse_deflate;
    let f = crate::process::read_file("treegdi.png");

    // we know the first IDAT chunk starts at 83 (avoid testing the scan_deflate code in a unit teast)
    let (idat_contents, deflate_stream) = parse_idat(&f[83..], 1).unwrap();

    println!("locations found: {:?}", idat_contents);
    assert_eq!(idat_contents.chunk_sizes, [65445, 65524, 40164]);
    assert_eq!(idat_contents.zlib_header, [120, 94]);

    let contents = parse_deflate(&deflate_stream).unwrap();

    assert_eq!(deflate_stream.len(), contents.compressed_size as usize);

    let total_chunk_length = idat_contents.total_chunk_length;

    let mut recreated = Vec::new();
    recreate_idat(&idat_contents, &deflate_stream, &mut recreated).unwrap();

    assert_eq!(total_chunk_length, recreated.len());

    assert!(f[83..83 + total_chunk_length] == recreated);
}
