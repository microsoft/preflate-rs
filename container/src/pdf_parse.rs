use preflate_rs::{PreflateError, Result, err_exit_code};

pub fn pdf_to_utf8(input: &[u8]) -> String {
    input
        .iter()
        .map(|&b| {
            match b {
                0x00..=0x7F => b as char,                // ASCII range same
                0x80 => '\u{20AC}',                      // EURO SIGN
                0x81..=0x8C | 0x8E..=0x9F => '\u{FFFD}', // Undefined mappings → replacement char
                0xA0..=0xFF => {
                    // Map selectively or fallback to Latin1
                    match b {
                        0xA9 => '\u{00A9}', // ©
                        0xAD => '\u{2013}', // en dash
                        0xAF => '\u{2014}', // em dash
                        0xD0 => '\u{2020}', // dagger
                        0xD1 => '\u{2021}', // double dagger
                        0xD2 => '\u{2022}', // bullet
                        0xD3 => '\u{2026}', // ellipsis
                        0xFE => '\u{00A0}', // non-breaking space
                        0xFF => '\u{2028}', // line separator
                        _ => b as char,     // Latin-1 fallback for others
                    }
                }
                _ => '\u{FFFD}', // replacement char for unmapped
            }
        })
        .collect()
}

fn decode_pdf_string(data: &[u8]) -> Result<String> {
    if data.len() >= 2 && data[0] == 0xFE && data[1] == 0xFF {
        // UTF-16BE with BOM
        if (data.len() - 2) % 2 != 0 {
            return err_exit_code(
                preflate_rs::ExitCode::InvalidIDat,
                "Invalid UTF-16BE string length",
            );
        }
        let utf16_data: Vec<u16> = data[2..]
            .chunks(2)
            .map(|chunk| (chunk[0] as u16) << 8 | (chunk[1] as u16))
            .collect();

        String::from_utf16(&utf16_data).map_err(|e| {
            PreflateError::new(
                preflate_rs::ExitCode::InvalidIDat,
                format!("UTF-16 decode error: {}", e),
            )
        })
    } else {
        // PDFDocEncoding fallback
        Ok(pdf_to_utf8(data))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PdfValue {
    Name(String),
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
    // Optional: add later
    // Array(Vec<PdfValue>),
    // Dictionary(HashMap<String, PdfValue>),
}

use std::collections::HashMap;

pub fn parse_pdf_dictionary(input: &[u8]) -> Result<HashMap<String, PdfValue>> {
    let mut result = HashMap::new();
    let mut pos = 0;

    // Skip leading '<<'
    if input.starts_with(b"<<") {
        pos += 2;
    }

    while pos < input.len() {
        skip_whitespace(input, &mut pos);

        if pos >= input.len() || input[pos] != b'/' {
            break;
        }

        // Parse key
        let key_start = pos + 1;
        let mut key_end = key_start;
        while key_end < input.len()
            && !is_whitespace(input[key_end])
            && !is_delimiter(input[key_end])
        {
            key_end += 1;
        }

        let key_bytes = &input[key_start..key_end];
        let key = pdf_to_utf8(key_bytes);
        pos = key_end;

        skip_whitespace(input, &mut pos);

        // Parse value
        let value = match input.get(pos) {
            Some(b'/') => {
                let (name, consumed) = parse_name(&input[pos..]);
                pos += consumed;
                PdfValue::Name(name)
            }
            Some(b'(') => {
                let (bytes, consumed) = parse_literal_string(&input[pos..])?;
                pos += consumed;
                PdfValue::String(decode_pdf_string(&bytes)?)
            }
            Some(b'-') | Some(b'+') | Some(b'0'..=b'9') => {
                let (number, consumed) = parse_number(&input[pos..])?;
                pos += consumed;
                PdfValue::Number(number)
            }
            Some(b't') if input.len() >= pos + 4 && &input[pos..pos + 4] == b"true" => {
                pos += 4;
                PdfValue::Boolean(true)
            }
            Some(b'f') if input.len() >= pos + 5 && &input[pos..pos + 5] == b"false" => {
                pos += 5;
                PdfValue::Boolean(false)
            }
            Some(b'n') if input.len() >= pos + 4 && &input[pos..pos + 4] == b"null" => {
                pos += 4;
                PdfValue::Null
            }
            _ => {
                // Unknown or unsupported type — skip
                break;
            }
        };

        result.insert(key, value);
    }

    Ok(result)
}

fn skip_whitespace(input: &[u8], pos: &mut usize) {
    while *pos < input.len() && is_whitespace(input[*pos]) {
        *pos += 1;
    }
}

fn parse_literal_string(input: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut output = Vec::new();
    let mut pos = 1; // skip '('
    let mut depth = 1;
    let mut escape = false;

    while pos < input.len() {
        let byte = input[pos];
        pos += 1;

        if escape {
            match byte {
                b'n' => output.push(b'\n'),
                b'r' => output.push(b'\r'),
                b't' => output.push(b'\t'),
                b'b' => output.push(0x08),
                b'f' => output.push(0x0C),
                b'(' => output.push(b'('),
                b')' => output.push(b')'),
                b'\\' => output.push(b'\\'),
                b'0'..=b'7' => {
                    let mut octal = vec![byte];
                    for _ in 0..2 {
                        if let Some(&next) = input.get(pos) {
                            if next >= b'0' && next <= b'7' {
                                octal.push(next);
                                pos += 1;
                            } else {
                                break;
                            }
                        }
                    }
                    if let Ok(val) =
                        u8::from_str_radix(std::str::from_utf8(&octal).unwrap_or("0"), 8)
                    {
                        output.push(val);
                    }
                }
                other => output.push(other),
            }
            escape = false;
        } else if byte == b'\\' {
            escape = true;
        } else if byte == b'(' {
            depth += 1;
            output.push(b'(');
        } else if byte == b')' {
            depth -= 1;
            if depth == 0 {
                break;
            }
            output.push(b')');
        } else {
            output.push(byte);
        }
    }

    Ok((output, pos))
}

fn parse_name(input: &[u8]) -> (String, usize) {
    let mut end = 1; // skip '/'
    while end < input.len() && !is_whitespace(input[end]) && !is_delimiter(input[end]) {
        end += 1;
    }
    let name_bytes = &input[1..end];
    (pdf_to_utf8(name_bytes), end)
}

fn parse_number(input: &[u8]) -> Result<(f64, usize)> {
    let mut end = 0;
    while end < input.len()
        && (input[end] == b'.'
            || input[end] == b'-'
            || input[end] == b'+'
            || input[end].is_ascii_digit())
    {
        end += 1;
    }
    let number_str = std::str::from_utf8(&input[..end])?;
    let number = number_str.parse()?;
    Ok((number, end))
}

fn is_whitespace(b: u8) -> bool {
    matches!(b, b'\x00' | b'\x09' | b'\x0A' | b'\x0C' | b'\x0D' | b' ')
}

fn is_delimiter(b: u8) -> bool {
    matches!(b, b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'/' | b'%')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_dictionary() {
        let input = b"<< >>";
        let result = parse_pdf_dictionary(input).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_string_value() {
        let input = b"<< /Title (RustLang) >>";
        let result = parse_pdf_dictionary(input).unwrap();
        assert_eq!(
            result.get("Title"),
            Some(&PdfValue::String("RustLang".to_string()))
        );
    }

    #[test]
    fn test_string_with_escape_sequences() {
        let input = b"<< /Note (Line\\nBreak\\tTabbed\\rReturn) >>";
        let result = parse_pdf_dictionary(input).unwrap();
        assert_eq!(
            result.get("Note"),
            Some(&PdfValue::String("Line\nBreak\tTabbed\rReturn".to_string()))
        );
    }

    #[test]
    fn test_string_with_octal_escape() {
        let input = b"<< /Data (Hello\\040World) >>";
        let result = parse_pdf_dictionary(input).unwrap();
        assert_eq!(
            result.get("Data"),
            Some(&PdfValue::String("Hello World".to_string()))
        );
    }

    #[test]
    fn test_nested_parentheses() {
        let input = b"<< /Comment (This (is) nested) >>";
        let result = parse_pdf_dictionary(input).unwrap();
        assert_eq!(
            result.get("Comment"),
            Some(&PdfValue::String("This (is) nested".to_string()))
        );
    }

    #[test]
    fn test_name_value() {
        let input = b"<< /Author /Alice >>";
        let result = parse_pdf_dictionary(input).unwrap();
        assert_eq!(
            result.get("Author"),
            Some(&PdfValue::Name("Alice".to_string()))
        );
    }

    #[test]
    fn test_utf16_value()
    {
        let input = b"<< /Title (\xFE\xFF\x00R\x00u\x00s\x00t) >>"; // "Rust" in UTF-16BE with BOM
        let result = parse_pdf_dictionary(input).unwrap();
        assert_eq!(
            result.get("Title"),
            Some(&PdfValue::String("Rust".to_string()))
        );
    }

    #[test]
    fn test_boolean_values() {
        let input = b"<< /Enabled true /Visible false >>";
        let result = parse_pdf_dictionary(input).unwrap();
        assert_eq!(result.get("Enabled"), Some(&PdfValue::Boolean(true)));
        assert_eq!(result.get("Visible"), Some(&PdfValue::Boolean(false)));
    }

    #[test]
    fn test_null_value() {
        let input = b"<< /Deleted null >>";
        let result = parse_pdf_dictionary(input).unwrap();
        assert_eq!(result.get("Deleted"), Some(&PdfValue::Null));
    }

    #[test]
    fn test_number_values() {
        let input = b"<< /Count 42 /Negative -7 /Float 3.14 >>";
        let result = parse_pdf_dictionary(input).unwrap();
        assert_eq!(result.get("Count"), Some(&PdfValue::Number(42.0)));
        assert_eq!(result.get("Negative"), Some(&PdfValue::Number(-7.0)));
        assert_eq!(result.get("Float"), Some(&PdfValue::Number(3.14)));
    }

    #[test]
    fn test_multiple_mixed_values() {
        let input = b"<< /Title (Rust) /Author /Bob /Pages 100 /Active true /Removed null >>";
        let result = parse_pdf_dictionary(input).unwrap();

        assert_eq!(
            result.get("Title"),
            Some(&PdfValue::String("Rust".to_string()))
        );
        assert_eq!(
            result.get("Author"),
            Some(&PdfValue::Name("Bob".to_string()))
        );
        assert_eq!(result.get("Pages"), Some(&PdfValue::Number(100.0)));
        assert_eq!(result.get("Active"), Some(&PdfValue::Boolean(true)));
        assert_eq!(result.get("Removed"), Some(&PdfValue::Null));
    }

    #[test]
    fn test_invalid_key_skips_parsing() {
        let input = b"<< Title (MissingSlash) >>"; // missing '/'
        let result = parse_pdf_dictionary(input).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_incomplete_string_does_not_panic() {
        let input = b"<< /Broken (This is incomplete >>";
        let _ = parse_pdf_dictionary(input).unwrap(); // shouldn't panic
    }

    #[test]
    fn test_ascii_identity() {
        let input = b"Hello, World!";
        let expected = "Hello, World!";
        assert_eq!(pdf_to_utf8(input), expected);
    }

    #[test]
    fn test_copyright_symbol() {
        let input = &[0xA9]; // ©
        let expected = "\u{00A9}";
        assert_eq!(pdf_to_utf8(input), expected);
    }

    #[test]
    fn test_en_and_em_dash() {
        let input = &[0xAD, 0xAF]; // en dash, em dash
        let expected = "\u{2013}\u{2014}"; // –—
        assert_eq!(pdf_to_utf8(input), expected);
    }

    #[test]
    fn test_typographic_characters() {
        let input = &[0xD0, 0xD1, 0xD2, 0xD3]; // †‡•…
        let expected = "\u{2020}\u{2021}\u{2022}\u{2026}";
        assert_eq!(pdf_to_utf8(input), expected);
    }

    #[test]
    fn test_euro_sign() {
        let input = &[0x80]; // €
        let expected = "\u{20AC}";
        assert_eq!(pdf_to_utf8(input), expected);
    }

    #[test]
    fn test_nonbreaking_space() {
        let input = &[0xFE];
        let expected = "\u{00A0}";
        assert_eq!(pdf_to_utf8(input), expected);
    }

    #[test]
    fn test_line_separator() {
        let input = &[0xFF];
        let expected = "\u{2028}";
        assert_eq!(pdf_to_utf8(input), expected);
    }

    #[test]
    fn test_unknown_byte_gives_replacement_char() {
        let input = &[0x90]; // Undefined in PDFDocEncoding
        let expected = "\u{FFFD}"; // Replacement character
        assert_eq!(pdf_to_utf8(input), expected);
    }

    #[test]
    fn test_mixed_ascii_and_pdfdoc_chars() {
        let input = &[b'H', b'i', b' ', 0xA9, b' ', 0x80]; // "Hi © €"
        let expected = "Hi \u{00A9} \u{20AC}";
        assert_eq!(pdf_to_utf8(input), expected);
    }

    #[test]
    fn test_parse_dictionary_with_pdfdoc_encoding_characters() {
        let input = b"<<        
        /Title (Rust Programming \xA9 2025)            
        /Note (\x80 price - valid until \xD3)            
        /Dash (\xAD\xAF)            
        /Fancy (\xD0\xD1\xD2)            
        /SpaceTest (\xFE\xFF)        >>";

        let result = parse_pdf_dictionary(input).unwrap();

        assert_eq!(
            result.get("Title"),
            Some(&PdfValue::String(
                "Rust Programming \u{00A9} 2025".to_string()
            ))
        );

        assert_eq!(
            result.get("Note"),
            Some(&PdfValue::String(
                "\u{20AC} price - valid until \u{2026}".to_string()
            ))
        );

        assert_eq!(
            result.get("Dash"),
            Some(&PdfValue::String("\u{2013}\u{2014}".to_string()))
        );

        assert_eq!(
            result.get("Fancy"),
            Some(&PdfValue::String("\u{2020}\u{2021}\u{2022}".to_string()))
        );

        assert_eq!(
            result.get("SpaceTest"),
            Some(&PdfValue::String("\u{00A0}\u{2028}".to_string()))
        );
    }
}
