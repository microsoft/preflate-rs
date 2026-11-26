use std::{io::Cursor, ops::Range};

use crate::{
    PreflateContainerConfig,
    container_common::charge_compression_effort,
    idat_parse::{IdatContents, PngHeader, parse_idat, parse_ihdr},
};

use lepton_jpeg::{DEFAULT_THREAD_POOL, EnabledFeatures};
use preflate_rs::{
    ExitCode, PlainText, PreflateConfig, PreflateStreamChunkResult, PreflateStreamProcessor,
    TokenPredictorParameters, err_exit_code,
};

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Read;

use preflate_rs::{PreflateError, Result};

/// The minimum size of a block that is considered for splitting into chunks
const MIN_BLOCKSIZE: usize = 1024;

pub struct FoundStream {
    pub chunk_type: FoundStreamType,
    pub corrections: Vec<u8>,
}

pub enum FoundStreamType {
    /// Deflate stream
    DeflateStream(TokenPredictorParameters, Box<PreflateStreamProcessor>),

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

fn small_idat_run_end(src: &[u8], start: usize, input_complete: bool) -> Option<usize> {
    let mut pos = start;
    let mut payload_len = 0usize;
    loop {
        let header = match src.get(pos..pos.checked_add(8)?) {
            Some(header) => header,
            None => return (input_complete && pos > start).then_some(src.len()),
        };
        if &header[4..8] != b"IDAT" {
            return (pos > start && (input_complete || src.len() - pos > 8)).then_some(pos);
        }
        let chunk_len = u32::from_be_bytes(header[..4].try_into().ok()?) as usize;
        payload_len = payload_len.checked_add(chunk_len)?;
        if payload_len >= 6 {
            return None;
        }
        pos = pos.checked_add(chunk_len)?.checked_add(12)?;
        if pos > src.len() {
            return input_complete.then_some(src.len());
        }
    }
}

fn first_bad_idat_chunk(src: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    loop {
        let header = src.get(pos..pos.checked_add(8)?)?;
        if &header[4..8] != b"IDAT" {
            return None;
        }
        let length = u32::from_be_bytes(header[..4].try_into().ok()?) as usize;
        let end = pos.checked_add(length)?.checked_add(8)?;
        let crc = src.get(end..end.checked_add(4)?)?;
        let mut hash = crc32fast::Hasher::new();
        hash.update(b"IDAT");
        hash.update(src.get(pos + 8..end)?);
        if hash.finalize().to_be_bytes() != crc {
            return Some(pos);
        }
        pos = end + 4;
    }
}

struct IdatSuffixCache {
    chunk_sizes: Vec<u32>,
    payload: Vec<u8>,
    next_chunk: usize,
    next_start: usize,
    payload_offset: usize,
    end: usize,
}

impl IdatSuffixCache {
    fn new(start: usize, idat: IdatContents, deflate: Vec<u8>) -> Self {
        let mut payload = Vec::with_capacity(deflate.len() + 6);
        payload.extend_from_slice(&idat.zlib_header);
        payload.extend_from_slice(&deflate);
        payload.extend_from_slice(&idat.addler32.to_be_bytes());
        let first_chunk = idat.chunk_sizes[0] as usize;
        Self {
            next_start: start + first_chunk + 12,
            end: start + idat.total_chunk_length,
            chunk_sizes: idat.chunk_sizes,
            payload,
            next_chunk: 1,
            payload_offset: first_chunk,
        }
    }

    fn next(&mut self, start: usize) -> Option<(&[u8], &[u32], usize)> {
        if start != self.next_start || self.next_chunk >= self.chunk_sizes.len() {
            return None;
        }
        let offset = self.payload_offset;
        let chunk = self.next_chunk;
        self.payload_offset += self.chunk_sizes[chunk] as usize;
        self.next_start += self.chunk_sizes[chunk] as usize + 12;
        self.next_chunk += 1;
        Some((
            &self.payload[offset..],
            &self.chunk_sizes[chunk..],
            self.end - start,
        ))
    }
}

pub enum FindStreamResult {
    None,
    Found(Range<usize>, FoundStream),
    ShortRead,
    EffortExceeded(PreflateError),
}

/// Scans for deflate streams in a zlib compressed file, decompresses the streams and
/// PNG IDAT chunks, and returns the locations of the streams.
pub fn find_compressable_stream(
    src: &[u8],
    prev_ihdr: &mut Option<PngHeader>,
    input_complete: bool,
    config: &PreflateContainerConfig,
    effort: &mut Option<u64>,
) -> FindStreamResult {
    let mut index: usize = 0;
    let mut next_nul = None;
    let mut nul_search_start = 0;
    let mut small_idat_end = 0;
    let mut next_small_idat = 0;
    let mut bad_idat_end = 0;
    let mut next_bad_idat = 0;
    let mut idat_cache: Option<IdatSuffixCache> = None;
    loop {
        let previous_index = index;
        let signature = next_signature(src, &mut index);
        let scanned = if signature.is_some() {
            index - previous_index + 1
        } else {
            src.len().saturating_sub(previous_index)
        };
        if let Err(e) = charge_compression_effort(effort, scanned) {
            return FindStreamResult::EffortExceeded(e);
        }
        let Some(signature) = signature else { break };
        match signature {
            Signature::Zlib(_) => {
                if let Err(e) = charge_compression_effort(effort, src.len() - index) {
                    return FindStreamResult::EffortExceeded(e);
                }
                let mut state = PreflateStreamProcessor::new(&config.preflate_config());

                let result = state.decompress_with_effort(&src[index + 2..], effort);
                if let Err(ref e) = result
                    && e.exit_code() == ExitCode::CompressionEffortLimit
                {
                    return FindStreamResult::EffortExceeded(e.clone());
                }
                if let Err(e) = charge_compression_effort(effort, state.plain_text().len()) {
                    return FindStreamResult::EffortExceeded(e);
                }
                if let Ok(res) = result {
                    if state.plain_text().len() > MIN_BLOCKSIZE {
                        index += 2;
                        return FindStreamResult::Found(
                            index..index + res.compressed_size,
                            FoundStream {
                                chunk_type: FoundStreamType::DeflateStream(
                                    res.parameters.unwrap(),
                                    Box::new(state),
                                ),
                                corrections: res.corrections,
                            },
                        );
                    }
                }
            }

            Signature::Gzip => {
                if let Err(e) = charge_compression_effort(effort, src.len() - index) {
                    return FindStreamResult::EffortExceeded(e);
                }
                let mut cursor = Cursor::new(&src[index..]);
                if skip_gzip_header(&mut cursor, |cursor| {
                    let start = index + cursor.position() as usize;
                    if next_nul.is_none_or(|position| position < start) {
                        let search_start = nul_search_start.max(start);
                        next_nul = src[search_start..]
                            .iter()
                            .position(|&byte| byte == 0)
                            .map(|offset| search_start + offset);
                        nul_search_start = next_nul.map_or(src.len(), |position| position + 1);
                    }
                    let position = next_nul.ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "GZIP string")
                    })?;
                    cursor.set_position((position - index + 1) as u64);
                    Ok(())
                })
                .is_ok()
                {
                    let start = index + cursor.position() as usize;

                    let mut state = PreflateStreamProcessor::new(&config.preflate_config());
                    let result = state.decompress_with_effort(&src[start..], effort);
                    if let Err(ref e) = result
                        && e.exit_code() == ExitCode::CompressionEffortLimit
                    {
                        return FindStreamResult::EffortExceeded(e.clone());
                    }
                    if let Err(e) = charge_compression_effort(effort, state.plain_text().len()) {
                        return FindStreamResult::EffortExceeded(e);
                    }
                    if let Ok(res) = result {
                        if state.plain_text().len() > MIN_BLOCKSIZE {
                            return FindStreamResult::Found(
                                start..start + res.compressed_size,
                                FoundStream {
                                    chunk_type: FoundStreamType::DeflateStream(
                                        res.parameters.unwrap(),
                                        Box::new(state),
                                    ),
                                    corrections: res.corrections,
                                },
                            );
                        }
                    }
                }
            }

            Signature::ZipLocalFileHeader => {
                if let Err(e) = charge_compression_effort(effort, src.len() - index) {
                    return FindStreamResult::EffortExceeded(e);
                }
                let result = parse_zip_stream(&src[index..], &config.preflate_config(), effort);
                if let Err(ref e) = result
                    && e.exit_code() == ExitCode::CompressionEffortLimit
                {
                    return FindStreamResult::EffortExceeded(e.clone());
                }
                if let Ok((header_size, res, state)) = result {
                    if let Err(e) = charge_compression_effort(effort, state.plain_text().len()) {
                        return FindStreamResult::EffortExceeded(e);
                    }
                    if state.plain_text().len() > MIN_BLOCKSIZE {
                        return FindStreamResult::Found(
                            index + header_size..index + header_size + res.compressed_size,
                            FoundStream {
                                chunk_type: FoundStreamType::DeflateStream(
                                    res.parameters.unwrap(),
                                    Box::new(state),
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
                    if index == next_bad_idat && real_start < bad_idat_end {
                        let length =
                            u32::from_be_bytes(src[real_start..index].try_into().unwrap()) as usize;
                        next_bad_idat = index + length + 12;
                        index += 1;
                        continue;
                    }
                    if let Some((bytes, sizes, length)) =
                        idat_cache.as_mut().and_then(|cache| cache.next(real_start))
                    {
                        if bytes.len() >= 6 {
                            if let Err(e) = charge_compression_effort(effort, bytes.len()) {
                                return FindStreamResult::EffortExceeded(e);
                            }
                            let png_header = *prev_ihdr;
                            *prev_ihdr = None;
                            let mut state = PreflateStreamProcessor::new(&config.preflate_config());
                            let payload = &bytes[2..bytes.len() - 4];
                            let result = state.decompress_with_effort(payload, effort);
                            if let Err(ref e) = result
                                && e.exit_code() == ExitCode::CompressionEffortLimit
                            {
                                return FindStreamResult::EffortExceeded(e.clone());
                            }
                            if let Err(e) =
                                charge_compression_effort(effort, state.plain_text().len())
                            {
                                return FindStreamResult::EffortExceeded(e);
                            }
                            if let Ok(res) = result
                                && res.compressed_size == payload.len()
                            {
                                if length > MIN_BLOCKSIZE {
                                    return FindStreamResult::Found(
                                        real_start..real_start + length,
                                        FoundStream {
                                            chunk_type: FoundStreamType::IDATDeflate(
                                                res.parameters.unwrap(),
                                                IdatContents {
                                                    chunk_sizes: sizes.to_vec(),
                                                    zlib_header: [bytes[0], bytes[1]],
                                                    total_chunk_length: length,
                                                    addler32: u32::from_be_bytes(
                                                        bytes[bytes.len() - 4..]
                                                            .try_into()
                                                            .unwrap(),
                                                    ),
                                                    png_header,
                                                },
                                                state.detach_plain_text(),
                                            ),
                                            corrections: res.corrections,
                                        },
                                    );
                                }
                                index = real_start + length;
                            }
                        }
                        index += 1;
                        continue;
                    }
                    if index == next_small_idat && index < small_idat_end {
                        let length =
                            u32::from_be_bytes(src[real_start..index].try_into().unwrap()) as usize;
                        next_small_idat = index + length + 12;
                        index += 1;
                        continue;
                    }
                    if let Err(e) = charge_compression_effort(effort, src.len() - real_start) {
                        return FindStreamResult::EffortExceeded(e);
                    }
                    if let Some(end) = small_idat_run_end(src, real_start, input_complete) {
                        small_idat_end = end;
                        let length =
                            u32::from_be_bytes(src[real_start..index].try_into().unwrap()) as usize;
                        next_small_idat = index + length + 12;
                        index += 1;
                        continue;
                    }
                    match parse_idat(*prev_ihdr, &src[real_start..]) {
                        Ok((idat_contents, payload)) => {
                            *prev_ihdr = None;
                            let mut state = PreflateStreamProcessor::new(&config.preflate_config());

                            let result = state.decompress_with_effort(&payload, effort);
                            if let Err(ref e) = result
                                && e.exit_code() == ExitCode::CompressionEffortLimit
                            {
                                return FindStreamResult::EffortExceeded(e.clone());
                            }
                            if let Err(e) =
                                charge_compression_effort(effort, state.plain_text().len())
                            {
                                return FindStreamResult::EffortExceeded(e);
                            }
                            if let Ok(res) = result
                                && res.compressed_size == payload.len()
                            {
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
                            if index == real_start + 4 && idat_contents.chunk_sizes.len() > 1 {
                                idat_cache =
                                    Some(IdatSuffixCache::new(real_start, idat_contents, payload));
                            }
                        }
                        Err(e) => {
                            if e.exit_code() == ExitCode::ShortRead && !input_complete {
                                // we don't have the whole IDAT chunk yet, so tell the caller they need to extend the buffer
                                return FindStreamResult::ShortRead;
                            }
                            if e.exit_code() == ExitCode::InvalidIDat
                                && let Some(bad) = first_bad_idat_chunk(src, real_start)
                            {
                                bad_idat_end = bad;
                                let length =
                                    u32::from_be_bytes(src[real_start..index].try_into().unwrap())
                                        as usize;
                                next_bad_idat = index + length + 12;
                            }
                        }
                    }
                }
            }
            Signature::JPEG => {
                if let Err(e) = charge_compression_effort(effort, src.len() - index) {
                    return FindStreamResult::EffortExceeded(e);
                }
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

fn skip_gzip_header<'a>(
    reader: &mut Cursor<&'a [u8]>,
    mut skip_string: impl FnMut(&mut Cursor<&'a [u8]>) -> Result<()>,
) -> Result<()> {
    let mut buffer = [0; 10];
    reader.read_exact(&mut buffer)?; // Read past the fixed 10-byte GZIP header

    if buffer[2] != 8 {
        return err_exit_code(ExitCode::InvalidDeflate, "Unsupported compression method");
    }

    if buffer[3] & 0x04 != 0 {
        // FEXTRA flag is set, read extra data
        let mut extra_len = [0; 2];
        reader.read_exact(&mut extra_len)?;
        let end = reader.position() as usize + usize::from(u16::from_le_bytes(extra_len));
        if end > reader.get_ref().len() {
            return err_exit_code(ExitCode::ShortRead, "Incomplete GZIP extra field");
        }
        reader.set_position(end as u64);
    }

    if buffer[3] & 0x08 != 0 {
        // FNAME flag is set, read null-terminated file name
        skip_string(reader)?;
    }

    if buffer[3] & 0x10 != 0 {
        // FCOMMENT flag is set, read null-terminated comment
        skip_string(reader)?;
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
            compressed_size: u64::from(binary_reader.read_u32::<LittleEndian>()?),
            uncompressed_size: u64::from(binary_reader.read_u32::<LittleEndian>()?),
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
    effort: &mut Option<u64>,
) -> Result<(usize, PreflateStreamChunkResult, PreflateStreamProcessor)> {
    let mut binary_reader = Cursor::new(&contents);

    // read the signature
    let zip_local_file_header = ZipLocalFileHeader::create_and_load(&mut binary_reader)?;
    let signature = zip_local_file_header.local_file_header_signature;
    if signature != ZIP_LOCAL_FILE_HEADER_SIGNATURE {
        return err_exit_code(ExitCode::InvalidDeflate, "No local header");
    }

    let deflate_start_position = binary_reader.position() as usize
        + usize::from(zip_local_file_header.file_name_length)
        + usize::from(zip_local_file_header.extra_field_length);
    if deflate_start_position > contents.len() {
        return err_exit_code(ExitCode::ShortRead, "Incomplete ZIP header fields");
    }

    // Handle the compressed DATA. Currently only Deflate (8) and uncompressed (0) are supported.
    if zip_local_file_header.compression_method == 8 {
        let mut state = PreflateStreamProcessor::new(config);

        let result = state.decompress_with_effort(&contents[deflate_start_position..], effort);
        if let Err(ref e) = result
            && e.exit_code() == ExitCode::CompressionEffortLimit
        {
            return Err(e.clone());
        }
        if let Ok(res) = result {
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
        &mut None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn skip_string(reader: &mut impl Read) -> Result<()> {
        while reader.read_u8()? != 0 {}
        Ok(())
    }

    #[test]
    fn skips_large_gzip_extra_without_allocating() {
        let mut header = vec![0x1f, 0x8b, 8, 0x04, 0, 0, 0, 0, 0, 0];
        header.extend_from_slice(&u16::MAX.to_le_bytes());
        header.resize(header.len() + u16::MAX as usize, 0);
        let mut reader = Cursor::new(header.as_slice());
        skip_gzip_header(&mut reader, skip_string).unwrap();
        assert_eq!(reader.position() as usize, header.len());

        reader = Cursor::new(&header[..header.len() - 1]);
        assert!(skip_gzip_header(&mut reader, skip_string).is_err());
    }

    #[test]
    fn repeated_gzip_names_do_not_rescan_unterminated_suffix() {
        let mut data = vec![b'A'; 128 * 1024];
        for position in (0..data.len() - 10).step_by(16) {
            data[position..position + 10]
                .copy_from_slice(&[0x1f, 0x8b, 8, 0x08, b'A', b'A', b'A', b'A', b'A', b'A']);
        }
        assert!(matches!(
            find_compressable_stream(
                &data,
                &mut None,
                true,
                &PreflateContainerConfig::default(),
                &mut None
            ),
            FindStreamResult::None
        ));
    }

    #[test]
    fn repeated_gzip_headers_skip_large_extra_fields_without_copying() {
        let mut data = vec![b'A'; 128 * 1024];
        for position in (0..data.len() - 12).step_by(16) {
            data[position..position + 12].copy_from_slice(&[
                0x1f, 0x8b, 8, 0x04, b'A', b'A', b'A', b'A', b'A', b'A', 0xff, 0xff,
            ]);
        }
        assert!(matches!(
            find_compressable_stream(
                &data,
                &mut None,
                true,
                &PreflateContainerConfig::default(),
                &mut None
            ),
            FindStreamResult::None
        ));
    }

    #[test]
    fn repeated_zip_headers_skip_large_fields_without_copying() {
        let mut data = vec![b'A'; 128 * 1024];
        for position in (0..data.len() - 30).step_by(32) {
            data[position..position + 30].copy_from_slice(&[
                b'P', b'K', 3, 4, 20, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0xff, 0xff,
            ]);
        }
        assert!(matches!(
            find_compressable_stream(
                &data,
                &mut None,
                true,
                &PreflateContainerConfig::default(),
                &mut None
            ),
            FindStreamResult::None
        ));
    }

    #[test]
    fn tiny_idat_run_is_examined_once() {
        let mut data = Vec::new();
        for _ in 0..2048 {
            data.extend_from_slice(&[0, 0, 0, 0]);
            data.extend_from_slice(b"IDAT");
            data.extend_from_slice(&crc32fast::hash(b"IDAT").to_be_bytes());
        }
        let run_end = data.len();
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(b"IEND");
        data.extend_from_slice(&crc32fast::hash(b"IEND").to_be_bytes());
        assert_eq!(small_idat_run_end(&data, 0, true), Some(run_end));
        assert!(matches!(
            find_compressable_stream(
                &data,
                &mut None,
                true,
                &PreflateContainerConfig::default(),
                &mut None
            ),
            FindStreamResult::None
        ));
        let mut zlib = vec![0x78, 0x9c];
        zlib.extend_from_slice(&crate::utils::read_file("compressed_zlib_level1.deflate"));
        assert!(matches!(
            find_compressable_stream(
                &zlib,
                &mut None,
                true,
                &PreflateContainerConfig::default(),
                &mut None
            ),
            FindStreamResult::Found(_, _)
        ));
        data.extend_from_slice(&zlib);
        match find_compressable_stream(
            &data,
            &mut None,
            true,
            &PreflateContainerConfig::default(),
            &mut None,
        ) {
            FindStreamResult::Found(range, _) => assert_eq!(range.start, run_end + 14),
            FindStreamResult::None => panic!("valid zlib stream after IDAT run was not found"),
            FindStreamResult::ShortRead => panic!("complete input requested more data"),
            FindStreamResult::EffortExceeded(e) => panic!("unlimited scan exceeded budget: {e}"),
        }

        data.truncate(run_end);
        assert_eq!(small_idat_run_end(&data, 0, true), Some(run_end));
        assert!(matches!(
            find_compressable_stream(
                &data,
                &mut None,
                true,
                &PreflateContainerConfig::default(),
                &mut None
            ),
            FindStreamResult::None
        ));
        assert!(matches!(
            find_compressable_stream(
                &data,
                &mut None,
                false,
                &PreflateContainerConfig::default(),
                &mut None
            ),
            FindStreamResult::ShortRead
        ));
    }

    #[test]
    fn cached_idat_suffix_keeps_valid_later_stream() {
        use crate::{PreflateContainerProcessor, ProcessBuffer, RecreateContainerProcessor};

        let mut zlib = vec![0x78, 0x9c];
        zlib.extend_from_slice(&crate::utils::read_file("compressed_zlib_level1.deflate"));
        zlib.extend_from_slice(&[0; 4]);
        let mut data = Vec::new();
        let chunks = std::iter::repeat_n(b"\0\0\0\0\0\0".as_slice(), 64)
            .chain(std::iter::once(zlib.as_slice()));
        for chunk in chunks {
            data.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
            data.extend_from_slice(b"IDAT");
            data.extend_from_slice(chunk);
            let mut crc = crc32fast::Hasher::new();
            crc.update(b"IDAT");
            crc.update(chunk);
            data.extend_from_slice(&crc.finalize().to_be_bytes());
        }
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(b"IEND");
        data.extend_from_slice(&crc32fast::hash(b"IEND").to_be_bytes());

        match find_compressable_stream(
            &data,
            &mut None,
            true,
            &PreflateContainerConfig::default(),
            &mut None,
        ) {
            FindStreamResult::Found(
                range,
                FoundStream {
                    chunk_type: FoundStreamType::IDATDeflate(_, idat, _),
                    ..
                },
            ) => {
                assert_eq!(range, 64 * 18..data.len() - 12);
                assert_eq!(idat.chunk_sizes, vec![zlib.len() as u32]);
                assert_eq!(idat.zlib_header, [0x78, 0x9c]);
            }
            _ => panic!("valid later IDAT stream not found"),
        }

        let config = PreflateContainerConfig::default();
        let encoded = PreflateContainerProcessor::new(&config, 1, false)
            .process_vec(&data)
            .unwrap();
        let decoded = RecreateContainerProcessor::new(4096)
            .process_vec(&encoded)
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn corrupt_idat_prefix_keeps_valid_later_stream() {
        let mut zlib = vec![0x78, 0x9c];
        zlib.extend_from_slice(&crate::utils::read_file("compressed_zlib_level1.deflate"));
        zlib.extend_from_slice(&[0; 4]);
        let mut data = Vec::new();
        let chunks = std::iter::repeat_n(b"\0\0\0\0\0\0".as_slice(), 64)
            .chain([b"broken".as_slice(), zlib.as_slice()]);
        for (i, chunk) in chunks.enumerate() {
            data.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
            data.extend_from_slice(b"IDAT");
            data.extend_from_slice(chunk);
            let mut crc = crc32fast::Hasher::new();
            crc.update(b"IDAT");
            crc.update(chunk);
            data.extend_from_slice(&(crc.finalize() ^ u32::from(i == 64)).to_be_bytes());
        }
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(b"IEND");
        data.extend_from_slice(&crc32fast::hash(b"IEND").to_be_bytes());
        match find_compressable_stream(
            &data,
            &mut None,
            true,
            &PreflateContainerConfig::default(),
            &mut None,
        ) {
            FindStreamResult::Found(range, _) => assert_eq!(range, 65 * 18..data.len() - 12),
            _ => panic!("valid IDAT suffix after bad CRC not found"),
        }
    }

    #[test]
    fn overlapping_idat_signature_inside_payload_is_still_scanned() {
        let mut zlib = vec![0x78, 0x9c];
        zlib.extend_from_slice(&crate::utils::read_file("compressed_zlib_level1.deflate"));
        zlib.extend_from_slice(&[0; 4]);

        let mut inner = Vec::new();
        inner.extend_from_slice(&(zlib.len() as u32).to_be_bytes());
        inner.extend_from_slice(b"IDAT");
        inner.extend_from_slice(&zlib);
        let mut crc = crc32fast::Hasher::new();
        crc.update(b"IDAT");
        crc.update(&zlib);
        inner.extend_from_slice(&crc.finalize().to_be_bytes());

        let mut data = Vec::new();
        data.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        data.extend_from_slice(b"IDAT");
        data.extend_from_slice(&inner);
        let mut crc = crc32fast::Hasher::new();
        crc.update(b"IDAT");
        crc.update(&inner);
        data.extend_from_slice(&crc.finalize().to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(b"IDAT");
        data.extend_from_slice(&crc32fast::hash(b"IDAT").to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(b"IEND");
        data.extend_from_slice(&crc32fast::hash(b"IEND").to_be_bytes());

        match find_compressable_stream(
            &data,
            &mut None,
            true,
            &PreflateContainerConfig::default(),
            &mut None,
        ) {
            FindStreamResult::Found(range, _) => assert_eq!(range, 8..8 + inner.len()),
            _ => panic!("overlapping valid IDAT stream was not found"),
        }
    }
}
