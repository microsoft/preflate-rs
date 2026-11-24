//! Filesystem attribute checks shared by diagnostic commands.
//! Identifies cloud-only placeholders so files can be skipped without hydration.

use std::fs::Metadata;

#[cfg(windows)]
pub fn cloud_only(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    cloud_attributes(metadata.file_attributes())
}

#[cfg(not(windows))]
pub fn cloud_only(_metadata: &Metadata) -> bool {
    false
}

#[cfg(any(windows, test))]
pub fn cloud_attributes(attributes: u32) -> bool {
    // OFFLINE, RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS.
    attributes & (0x1000 | 0x40000 | 0x400000) != 0
}
