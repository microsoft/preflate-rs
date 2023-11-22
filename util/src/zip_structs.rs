use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Read, Seek, SeekFrom};

pub const ZIP_LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x04034b50;
pub const ZIP64_EXTENDED_INFORMATION_TYPE_TAG: u16 = 0x0001;

#[derive(Clone)]
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
        let mut zip_local_file_header = Self::new();
        zip_local_file_header.load(binary_reader)?;
        Ok(zip_local_file_header)
    }

    fn new() -> Self {
        ZipLocalFileHeader {
            local_file_header_signature: 0,
            version_needed_to_extract: 0,
            general_purpose_bit_flag: 0,
            compression_method: 0,
            last_mod_file_time: 0,
            last_mod_file_date: 0,
            crc32: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            file_name_length: 0,
            extra_field_length: 0,
        }
    }

    fn load<R: Read>(&mut self, binary_reader: &mut R) -> anyhow::Result<()> {
        self.local_file_header_signature = binary_reader.read_u32::<LittleEndian>()?;
        self.version_needed_to_extract = binary_reader.read_u16::<LittleEndian>()?;
        self.general_purpose_bit_flag = binary_reader.read_u16::<LittleEndian>()?;
        self.compression_method = binary_reader.read_u16::<LittleEndian>()?;
        self.last_mod_file_time = binary_reader.read_u16::<LittleEndian>()?;
        self.last_mod_file_date = binary_reader.read_u16::<LittleEndian>()?;
        self.crc32 = binary_reader.read_u32::<LittleEndian>()?;
        self.compressed_size = binary_reader.read_u32::<LittleEndian>()? as u64;
        self.uncompressed_size = binary_reader.read_u32::<LittleEndian>()? as u64;
        self.file_name_length = binary_reader.read_u16::<LittleEndian>()?;
        self.extra_field_length = binary_reader.read_u16::<LittleEndian>()?;
        Ok(())
    }
}

pub struct ZipExtendedInformationHeader {
    pub header_id: u16,
    pub data_size: u16,
}

impl ZipExtendedInformationHeader {
    pub fn create_and_load<R: Read>(binary_reader: &mut R) -> anyhow::Result<Self> {
        let mut zip_ext_info_header = Self::new();
        zip_ext_info_header.load(binary_reader)?;
        Ok(zip_ext_info_header)
    }

    fn new() -> Self {
        ZipExtendedInformationHeader {
            header_id: 0,
            data_size: 0,
        }
    }

    fn load<R: Read>(&mut self, binary_reader: &mut R) -> anyhow::Result<()> {
        self.header_id = binary_reader.read_u16::<LittleEndian>()?;
        self.data_size = binary_reader.read_u16::<LittleEndian>()?;
        Ok(())
    }
}

pub struct Zip64ExtendedInformation {
    pub size_original: u64,
    pub size_compressed: u64,
    // Also in the Zip64 Extended Information Extra Field, but not
    // interesting to us currently...
    pub relative_header_offset: u64,
    pub disk_start_number: u32,
}

impl Zip64ExtendedInformation {
    /// Loads a Zip 64 extended header based on the existence of a proper record type and
    /// the values of the current header fields being 0xFFFF or 0xFFFFFFFF
    /// # Arguments
    /// * `binaryReader`
    /// * `f_local_header` - true if this is a local header which must contain both original and compressed file size fields
    /// * `extended_info_size_in_bytes` - size of the extended
    /// * `size_original32` - value in current header
    /// * `size_compressed32` - value in current header
    /// * `relative_header_offset32` - value in current header..pass 0 if current header doesn't have this field
    /// * `diskstart_number16` - value in current header..pass 0 if current header doesn't have this field
    pub fn create_and_load<R: Read + Seek>(
        binary_reader: &mut R,
        f_local_header: bool,
        extended_info_size_in_bytes: u32,
        size_original32: u32,
        size_compressed32: u32,
        relative_header_offset32: u32,
        diskstart_number16: u16,
    ) -> anyhow::Result<Self> {
        let mut zip_ext_info_header = Self::new();
        zip_ext_info_header.load(
            binary_reader,
            f_local_header,
            extended_info_size_in_bytes,
            size_original32,
            size_compressed32,
            relative_header_offset32,
            diskstart_number16,
        )?;
        Ok(zip_ext_info_header)
    }

    fn new() -> Self {
        Zip64ExtendedInformation {
            size_original: 0,
            size_compressed: 0,
            relative_header_offset: 0,
            disk_start_number: 0,
        }
    }

    fn load<R: Read + Seek>(
        &mut self,
        binary_reader: &mut R,
        f_local_header: bool,
        extended_info_size_in_bytes: u32,
        size_original32: u32,
        size_compressed32: u32,
        relative_header_offset32: u32,
        diskstart_number16: u16,
    ) -> anyhow::Result<()> {
        let mut unprocessed_extended_info_size_in_bytes = extended_info_size_in_bytes;

        let result = self.load_without_seek_forward(
            binary_reader,
            f_local_header,
            &mut unprocessed_extended_info_size_in_bytes,
            size_original32,
            size_compressed32,
            relative_header_offset32,
            diskstart_number16,
        );

        if unprocessed_extended_info_size_in_bytes > 0 {
            binary_reader.seek(SeekFrom::Current(
                unprocessed_extended_info_size_in_bytes as i64,
            ))?;
        }

        result
    }

    fn load_without_seek_forward<R: Read>(
        &mut self,
        binary_reader: &mut R,
        f_local_header: bool,
        unprocessed_extended_info_size_in_bytes: &mut u32,
        size_original32: u32,
        size_compressed32: u32,
        relative_header_offset32: u32,
        diskstart_number16: u16,
    ) -> anyhow::Result<()> {
        if f_local_header {
            // Local Header must include BOTH original and compressed file size fields (see APPNOTE.TXT)
            if *unprocessed_extended_info_size_in_bytes < 16 {
                return Err(anyhow::Error::msg("EndOfStreamException"));
            }

            self.size_original = binary_reader.read_u64::<LittleEndian>()?;
            self.size_compressed = binary_reader.read_u64::<LittleEndian>()?;
            *unprocessed_extended_info_size_in_bytes -= 16;

            if *unprocessed_extended_info_size_in_bytes == 0 {
                return Ok(());
            }
        } else {
            if size_original32 == 0xFFFFFFFF
            // Only expect this field if 32bit field is 0xFFFFFFFF
            {
                if *unprocessed_extended_info_size_in_bytes < 8 {
                    return Err(anyhow::Error::msg("EndOfStreamException"));
                }

                self.size_original = binary_reader.read_u64::<LittleEndian>()?;
                *unprocessed_extended_info_size_in_bytes -= 8;
            }

            if size_compressed32 == 0xFFFFFFFF {
                // Only expect this field if 32bit field is 0xFFFFFFFF
                if *unprocessed_extended_info_size_in_bytes < 8 {
                    return Err(anyhow::Error::msg("EndOfStreamException"));
                }

                self.size_compressed = binary_reader.read_u64::<LittleEndian>()?;
                *unprocessed_extended_info_size_in_bytes -= 8;
            }
        }

        if relative_header_offset32 == 0xFFFFFFFF {
            // Only expect this field if 32bit field is 0xFFFFFFFF
            if *unprocessed_extended_info_size_in_bytes < 8 {
                return Err(anyhow::Error::msg("EndOfStreamException"));
            }

            self.relative_header_offset = binary_reader.read_u64::<LittleEndian>()?;
            *unprocessed_extended_info_size_in_bytes -= 8;
        }

        if diskstart_number16 == 0xFFFF {
            // Only expect this field if 16bit field is 0xFFFF
            if *unprocessed_extended_info_size_in_bytes < 4 {
                return Err(anyhow::Error::msg("EndOfStreamException"));
            }

            self.disk_start_number = binary_reader.read_u32::<LittleEndian>()?;
            *unprocessed_extended_info_size_in_bytes -= 4;
        }

        Ok(())
    }
}
