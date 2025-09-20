use std::io::{Read, Write};

use byteorder::{ReadBytesExt, WriteBytesExt};

use preflate_rs::{ExitCode, Result, err_exit_code};

use crate::container_processor::{read_varint, write_varint};

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

    /// The PNG header if there was one
    pub png_header: Option<PngHeader>,
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

        let mut png_header = None;
        if let Some(color_type) = PngColorType::parse(r.read_u8()?) {
            let width = read_varint(r)?;
            let height = read_varint(r)?;

            png_header = Some(PngHeader {
                width,
                height,
                color_type,
            });
        }

        // total chunk size is the sum of all the chunk sizes + 2 bytes for the zlib header + 4 bytes for the addler32
        let total_chunk_length = chunk_sizes.iter().sum::<u32>() + 2 + 4;

        Ok(IdatContents {
            chunk_sizes,
            zlib_header,
            total_chunk_length: total_chunk_length as usize,
            addler32: u32::from_be_bytes(addler32),
            png_header,
        })
    }

    pub fn write_to_bytestream(&self, w: &mut impl std::io::Write) -> std::io::Result<()> {
        for &chunk_size in self.chunk_sizes.iter() {
            write_varint(w, chunk_size)?;
        }
        write_varint(w, 0)?;

        w.write_all(&self.zlib_header)?;

        w.write_all(&self.addler32.to_be_bytes())?;

        if let Some(png_header) = &self.png_header {
            w.write_u8(png_header.color_type as u8)?;
            write_varint(w, png_header.width)?;
            write_varint(w, png_header.height)?;
        } else {
            // no PNG header
            w.write_u8(0xff)?;
        }

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
        png_header: Some(PngHeader {
            width: 5,
            height: 5,
            color_type: PngColorType::RGB,
        }),
    };

    let mut buffer = Vec::new();
    idat.write_to_bytestream(&mut buffer).unwrap();

    let mut cur = std::io::Cursor::new(&buffer);

    let idat2 = IdatContents::read_from_bytestream(&mut cur).unwrap();

    assert_eq!(idat, idat2);
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct PngHeader {
    pub width: u32,
    pub height: u32,
    pub color_type: PngColorType,
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum PngColorType {
    // Grayscale = 0,
    RGB = 2,
    // 3 = Pallete not supported
    //GrayscaleAlpha = 4,
    RGBA = 6,
}

impl PngColorType {
    fn parse(byte: u8) -> Option<Self> {
        match byte {
            //0 => Some(PngColorType::Grayscale),
            2 => Some(PngColorType::RGB),
            //4 => Some(PngColorType::GrayscaleAlpha),
            6 => Some(PngColorType::RGBA),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn bytes_per_pixel(&self) -> usize {
        match self {
            //PngColorType::Grayscale => 1,
            PngColorType::RGB => 3,
            //PngColorType::GrayscaleAlpha => 2,
            PngColorType::RGBA => 4,
        }
    }
}

pub fn parse_ihdr(ihdr_chunk: &[u8]) -> Result<PngHeader> {
    if ihdr_chunk.len() < 13 + 8 {
        return err_exit_code(ExitCode::ShortRead, "Need more data");
    }

    let ihdr_length =
        u32::from_be_bytes([ihdr_chunk[0], ihdr_chunk[1], ihdr_chunk[2], ihdr_chunk[3]]) as usize;

    if ihdr_length != 13 {
        return err_exit_code(ExitCode::ShortRead, "Need more data");
    }

    let ihdr_data = &ihdr_chunk[8..ihdr_length + 8];

    if ihdr_data[8] != 8 {
        log::debug!("IHDR bit depth cannot be {}", ihdr_data[8]);
        return err_exit_code(ExitCode::InvalidIDat, "IHDR bit depth is not 8");
    }

    let width = u32::from_be_bytes(ihdr_data[0..4].try_into().unwrap());
    let height = u32::from_be_bytes(ihdr_data[4..8].try_into().unwrap());
    if let Some(color_type) = PngColorType::parse(ihdr_data[9]) {
        Ok(PngHeader {
            width,
            height,
            color_type,
        })
    } else {
        log::debug!("IHDR unsupported color type {}", ihdr_data[9]);
        return err_exit_code(ExitCode::InvalidIDat, "IHDR unsupported color type");
    }
}

/// parses PNG IDAT chunks starting from the first one and returns the embedded deflate stream and the IDAT chunk sizes
pub fn parse_idat(
    png_header: Option<PngHeader>,
    png_idat_stream: &[u8],
) -> Result<(IdatContents, Vec<u8>)> {
    if png_idat_stream.len() < 12 || &png_idat_stream[4..8] != b"IDAT" {
        return err_exit_code(ExitCode::InvalidIDat, "No IDAT chunk found");
    }

    // track the chunk sizes we've seen
    let mut pos = 0;
    let mut found_end = false;
    let mut chunk_ranges = Vec::new();

    let mut total_length = 0;

    // need at least 8 bytes for the chunk length and type
    while pos < png_idat_stream.len() - 8 {
        // png chunks start with the length of the chunk
        let chunk_len = u32::from_be_bytes([
            png_idat_stream[pos],
            png_idat_stream[pos + 1],
            png_idat_stream[pos + 2],
            png_idat_stream[pos + 3],
        ]) as usize;

        // now look at the chunk type. We only want IDAT chunks
        // and they have to be consecutive, so stop once we see
        // that is not an IDAT. Usually this is IEND.
        let chunk_type = &png_idat_stream[pos + 4..pos + 8];
        if chunk_type != b"IDAT" {
            found_end = true;
            break;
        }

        // stop if we don't have enough data for the chunk
        if pos + chunk_len + 12 > png_idat_stream.len() {
            break;
        }

        let chunk_start = pos + 8;
        let chunk_end = pos + chunk_len + 8;
        let chunk = &png_idat_stream[chunk_start..chunk_end];
        total_length += chunk_len;

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

        chunk_ranges.push((chunk_start, chunk_end));

        pos += chunk_len + 12;
    }

    if !found_end {
        return err_exit_code(ExitCode::ShortRead, "Need more png data");
    }

    let mut deflate_stream = Vec::with_capacity(total_length);
    let mut idat_chunk_sizes = Vec::new();

    for &(start, end) in chunk_ranges.iter() {
        deflate_stream.extend_from_slice(&png_idat_stream[start..end]);
        idat_chunk_sizes.push((end - start) as u32);
    }

    log::debug!("IDAT boundaries: {:?}", idat_chunk_sizes);

    if deflate_stream.len() < 6 {
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
            png_header,
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

fn paeth_predictor(a: u8, b: u8, c: u8) -> u8 {
    let a = a as i32;
    let b = b as i32;
    let c = c as i32;
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        a as u8
    } else if pb <= pc {
        b as u8
    } else {
        c as u8
    }
}
/// Undoes the PNG filters on an image to get back the original bitmap
/// Used by webp compression to undo the PNG filters before applying
#[allow(dead_code)]
pub fn undo_png_filters(
    filtered: &[u8],
    width: usize,
    height: usize,
    bpp: usize,
) -> (Vec<u8>, Vec<u8>) {
    let stride = width * bpp;
    let mut bitmap = Vec::with_capacity(height * stride);
    let mut prev_scanline: Vec<u8> = vec![0; stride];
    let mut filters = Vec::with_capacity(height);

    let mut i = 0;
    for _ in 0..height {
        let filter_type = filtered[i];
        filters.push(filter_type);

        let scanline = &filtered[i + 1..i + 1 + stride];
        let mut unfiltered = vec![0u8; stride];

        for x in 0..stride {
            let left = if x >= bpp { unfiltered[x - bpp] } else { 0 };
            let above = prev_scanline[x];
            let upper_left = if x >= bpp { prev_scanline[x - bpp] } else { 0 };

            unfiltered[x] = match filter_type {
                0 => scanline[x],
                1 => scanline[x].wrapping_add(left),
                2 => scanline[x].wrapping_add(above),
                3 => scanline[x].wrapping_add(((left as u16 + above as u16) / 2) as u8),
                4 => scanline[x].wrapping_add(paeth_predictor(left, above, upper_left)),
                _ => panic!("Unknown filter type: {}", filter_type),
            };
        }

        bitmap.extend_from_slice(&unfiltered);
        prev_scanline = unfiltered;
        i += 1 + stride;
    }

    (bitmap, filters)
}

#[allow(dead_code)]
pub fn apply_png_filters_with_types(
    bitmap: &[u8],
    width: usize,
    height: usize,
    source_bbp: usize,
    target_bpp: usize,
    filter_types: &[u8],
) -> Vec<u8> {
    let source_stride = width * source_bbp;
    let target_stride = width * target_bpp;

    let mut filtered = Vec::with_capacity(height * (1 + target_stride));
    let mut prev_scanline: Vec<u8> = vec![0; target_stride];
    let mut rgba = vec![0u8; target_stride];
    let mut encoded = vec![0u8; target_stride];

    for row in 0..height {
        let filter_type = filter_types[row];
        let offset = row * source_stride;

        let scanline = if source_bbp == 3 && target_bpp == 4 {
            // convert from RGB to RGBA. Webp does this if the alpha channel is all 255
            for x in 0..width {
                rgba[x * 4] = bitmap[offset + x * 3];
                rgba[x * 4 + 1] = bitmap[offset + x * 3 + 1];
                rgba[x * 4 + 2] = bitmap[offset + x * 3 + 2];
                rgba[x * 4 + 3] = 255;
            }
            rgba.as_slice()
        } else {
            &bitmap[offset..offset + source_stride]
        };

        process_line(
            target_bpp,
            target_stride,
            &prev_scanline,
            filter_type,
            scanline,
            &mut encoded,
        );

        filtered.push(filter_type);
        filtered.extend_from_slice(&encoded);
        prev_scanline.copy_from_slice(scanline);
    }

    filtered
}

fn process_line(
    target_bpp: usize,
    target_stride: usize,
    prev_scanline: &[u8],
    filter_type: u8,
    scanline: &[u8],
    encoded: &mut [u8],
) {
    for x in 0..target_stride {
        let left = if x >= target_bpp {
            scanline[x - target_bpp]
        } else {
            0
        };
        let above = prev_scanline[x];
        let upper_left = if x >= target_bpp {
            prev_scanline[x - target_bpp]
        } else {
            0
        };

        encoded[x] = match filter_type {
            0 => scanline[x],
            1 => scanline[x].wrapping_sub(left),
            2 => scanline[x].wrapping_sub(above),
            3 => scanline[x].wrapping_sub(((left as u16 + above as u16) / 2) as u8),
            4 => scanline[x].wrapping_sub(paeth_predictor(left, above, upper_left)),
            _ => panic!("Unknown filter type: {}", filter_type),
        };
    }
}

#[test]
fn parse_and_recreate_png() {
    let f = crate::utils::read_file("treegdi.png");

    // we know the first IDAT chunk starts at 83 (avoid testing the scan_deflate code in a unit test)
    let (idat_contents, deflate_stream) =
        parse_idat(Some(parse_ihdr(&f[8..8 + 8 + 13]).unwrap()), &f[83..]).unwrap();

    println!("locations found: {:?}", idat_contents);
    assert_eq!(idat_contents.chunk_sizes, [65445, 65524, 40164]);
    assert_eq!(idat_contents.zlib_header, [120, 94]);

    let contents = miniz_oxide::inflate::decompress_to_vec(&deflate_stream).unwrap();
    assert_eq!(
        adler32::adler32(std::io::Cursor::new(&contents)).unwrap(),
        idat_contents.addler32
    );

    let total_chunk_length = idat_contents.total_chunk_length;

    let mut recreated = Vec::new();
    recreate_idat(&idat_contents, &deflate_stream, &mut recreated).unwrap();

    assert_eq!(total_chunk_length, recreated.len());

    assert!(f[83..83 + total_chunk_length] == recreated);
}

#[test]
fn test_png_filter_round_trip_with_explicit_filters() {
    let width = 6;
    let height = 5;
    let bpp = 3;
    let mut bitmap = vec![0u8; width * height * bpp];

    for (i, byte) in bitmap.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    // Encode using all filter types
    // 0 = None, 1 = Sub, 2 = Up, 3 = Average, 4 = Paeth
    let filter_types = [0, 1, 2, 3, 4].to_vec();
    let filtered = apply_png_filters_with_types(&bitmap, width, height, bpp, bpp, &filter_types);

    // Decode and extract actual used filters
    let (decoded, extracted_filters) = undo_png_filters(&filtered, width, height, bpp);
    assert_eq!(bitmap, decoded, "Decoding did not recover original bitmap");
    assert_eq!(filter_types, extracted_filters, "Filter tracking mismatch");

    // Re-encode using extracted filters
    let reencoded =
        apply_png_filters_with_types(&decoded, width, height, bpp, bpp, &extracted_filters);
    assert_eq!(
        filtered, reencoded,
        "Re-encoding did not match original filtered data"
    );
}
