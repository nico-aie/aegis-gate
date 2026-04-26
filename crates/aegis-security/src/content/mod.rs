pub mod archive;
pub mod icap;

/// Magic-byte file type detection.
///
/// Detects file type from the first bytes of a payload (not Content-Type).
///
/// Known file type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileType {
    Jpeg,
    Png,
    Gif,
    Pdf,
    Zip,
    Gzip,
    Exe,
    Elf,
    MachO,
    Wasm,
    Unknown,
}

/// Detect file type from magic bytes.
pub fn detect_file_type(data: &[u8]) -> FileType {
    if data.len() < 4 {
        return FileType::Unknown;
    }

    match &data[..4] {
        [0xFF, 0xD8, 0xFF, _] => FileType::Jpeg,
        [0x89, 0x50, 0x4E, 0x47] => FileType::Png,
        [0x47, 0x49, 0x46, 0x38] => FileType::Gif,
        [0x25, 0x50, 0x44, 0x46] => FileType::Pdf,
        [0x50, 0x4B, 0x03, 0x04] => FileType::Zip,
        [0x1F, 0x8B, _, _] => FileType::Gzip,
        [0x4D, 0x5A, _, _] => FileType::Exe,
        [0x7F, 0x45, 0x4C, 0x46] => FileType::Elf,
        [0xCF, 0xFA, 0xED, 0xFE] | [0xFE, 0xED, 0xFA, 0xCF] => FileType::MachO,
        [0x00, 0x61, 0x73, 0x6D] => FileType::Wasm,
        _ => FileType::Unknown,
    }
}

/// Check if a file type is in the allowed list.
pub fn is_allowed(file_type: &FileType, allowed: &[FileType]) -> bool {
    allowed.contains(file_type) || *file_type == FileType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_jpeg() {
        assert_eq!(detect_file_type(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]), FileType::Jpeg);
    }

    #[test]
    fn detect_png() {
        assert_eq!(detect_file_type(&[0x89, 0x50, 0x4E, 0x47, 0x0D]), FileType::Png);
    }

    #[test]
    fn detect_gif() {
        assert_eq!(detect_file_type(&[0x47, 0x49, 0x46, 0x38, 0x39]), FileType::Gif);
    }

    #[test]
    fn detect_pdf() {
        assert_eq!(detect_file_type(b"%PDF-1.4"), FileType::Pdf);
    }

    #[test]
    fn detect_zip() {
        assert_eq!(detect_file_type(&[0x50, 0x4B, 0x03, 0x04, 0x00]), FileType::Zip);
    }

    #[test]
    fn detect_gzip() {
        assert_eq!(detect_file_type(&[0x1F, 0x8B, 0x08, 0x00, 0x00]), FileType::Gzip);
    }

    #[test]
    fn detect_exe() {
        assert_eq!(detect_file_type(&[0x4D, 0x5A, 0x90, 0x00, 0x03]), FileType::Exe);
    }

    #[test]
    fn detect_elf() {
        assert_eq!(detect_file_type(&[0x7F, 0x45, 0x4C, 0x46, 0x02]), FileType::Elf);
    }

    #[test]
    fn detect_wasm() {
        assert_eq!(detect_file_type(&[0x00, 0x61, 0x73, 0x6D, 0x01]), FileType::Wasm);
    }

    #[test]
    fn unknown_data() {
        assert_eq!(detect_file_type(b"Hello World"), FileType::Unknown);
    }

    #[test]
    fn short_data() {
        assert_eq!(detect_file_type(&[0xFF, 0xD8]), FileType::Unknown);
    }

    #[test]
    fn exe_upload_to_image_only_rejected() {
        let allowed = vec![FileType::Jpeg, FileType::Png, FileType::Gif];
        let exe_data = &[0x4D, 0x5A, 0x90, 0x00, 0x03];
        let ft = detect_file_type(exe_data);
        assert!(!is_allowed(&ft, &allowed));
    }

    #[test]
    fn jpeg_upload_to_image_allowed() {
        let allowed = vec![FileType::Jpeg, FileType::Png, FileType::Gif];
        let jpeg_data = &[0xFF, 0xD8, 0xFF, 0xE0, 0x00];
        let ft = detect_file_type(jpeg_data);
        assert!(is_allowed(&ft, &allowed));
    }

    #[test]
    fn unknown_type_always_allowed() {
        let allowed = vec![FileType::Jpeg];
        assert!(is_allowed(&FileType::Unknown, &allowed));
    }
}
