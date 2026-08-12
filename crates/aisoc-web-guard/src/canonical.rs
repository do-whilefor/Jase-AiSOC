use percent_encoding::percent_decode_str;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

const MAX_CANONICAL_BYTES: usize = 256 * 1024;
const MAX_PERCENT_DECODE_PASSES: usize = 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CanonicalizationError {
    #[error("canonicalized value exceeds size limit")]
    TooLarge,
    #[error("URI contains invalid control characters")]
    ControlCharacter,
    #[error("value contains malformed percent encoding")]
    InvalidPercentEncoding,
    #[error("percent-decoded value is not valid UTF-8")]
    InvalidUtf8,
}

pub fn canonicalize_text(input: &str) -> Result<String, CanonicalizationError> {
    if input.len() > MAX_CANONICAL_BYTES {
        return Err(CanonicalizationError::TooLarge);
    }
    reject_controls(input)?;

    let mut value = input.to_owned();
    for _ in 0..MAX_PERCENT_DECODE_PASSES {
        if !value.as_bytes().contains(&b'%') {
            break;
        }
        let decoded = percent_decode_str(&value)
            .decode_utf8()
            .map_err(|_| CanonicalizationError::InvalidUtf8)?
            .into_owned();
        if decoded == value {
            break;
        }
        if decoded.len() > MAX_CANONICAL_BYTES {
            return Err(CanonicalizationError::TooLarge);
        }
        value = decoded;
    }
    value = decode_security_relevant_html_entities(&value);
    value = value.nfkc().collect::<String>();
    reject_controls(&value)?;
    if value.len() > MAX_CANONICAL_BYTES {
        return Err(CanonicalizationError::TooLarge);
    }
    Ok(value)
}

pub fn canonicalize_uri(input: &str) -> Result<String, CanonicalizationError> {
    validate_percent_encoding(input)?;
    let canonical = canonicalize_text(input)?;
    let (path, query) = canonical
        .split_once('?')
        .map_or((canonical.as_str(), None), |(path, query)| (path, Some(query)));
    let normalized_path = normalize_path(path);
    Ok(match query {
        Some(query) => format!("{normalized_path}?{query}"),
        None => normalized_path,
    })
}

fn normalize_path(path: &str) -> String {
    let slash_normalized = path.replace('\\', "/");
    let path = slash_normalized.as_str();
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/') && path.len() > 1;
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                let _ = segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    let mut result = if absolute { "/".to_owned() } else { String::new() };
    result.push_str(&segments.join("/"));
    if trailing && !result.ends_with('/') {
        result.push('/');
    }
    if result.is_empty() {
        result.push('/');
    }
    result
}

fn validate_percent_encoding(value: &str) -> Result<(), CanonicalizationError> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err(CanonicalizationError::InvalidPercentEncoding);
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn reject_controls(value: &str) -> Result<(), CanonicalizationError> {
    if value
        .chars()
        .any(|ch| ch == '\0' || ch == '\r' || ch == '\n' || ch == '\u{7f}')
    {
        return Err(CanonicalizationError::ControlCharacter);
    }
    Ok(())
}

fn decode_security_relevant_html_entities(input: &str) -> String {
    let mut output = input.to_owned();
    for (from, to) in [
        ("&lt;", "<"),
        ("&#60;", "<"),
        ("&#x3c;", "<"),
        ("&#X3C;", "<"),
        ("&gt;", ">"),
        ("&#62;", ">"),
        ("&#x3e;", ">"),
        ("&#X3E;", ">"),
        ("&quot;", "\""),
        ("&#34;", "\""),
        ("&#x22;", "\""),
        ("&#39;", "'"),
        ("&#x27;", "'"),
        ("&amp;", "&"),
    ] {
        output = output.replace(from, to);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_multiple_percent_encoding_layers() {
        assert_eq!(canonicalize_text("%252e%252e%252f").unwrap(), "../");
    }

    #[test]
    fn normalizes_unicode_compatibility_forms() {
        assert_eq!(canonicalize_text("ＳＥＬＥＣＴ").unwrap(), "SELECT");
    }

    #[test]
    fn text_allows_literal_percent_characters() {
        assert_eq!(canonicalize_text("progress=100%").unwrap(), "progress=100%");
    }

    #[test]
    fn text_decodes_valid_percent_sequences_even_with_literal_percent() {
        assert_eq!(
            canonicalize_text("progress=100%&payload=%3cscript%3e").unwrap(),
            "progress=100%&payload=<script>"
        );
    }

    #[test]
    fn canonical_uri_resolves_dot_segments() {
        assert_eq!(canonicalize_uri("/a/b/../c?q=1").unwrap(), "/a/c?q=1");
    }

    #[test]
    fn rejects_malformed_percent_encoding() {
        assert_eq!(
            canonicalize_uri("/ok%2").unwrap_err(),
            CanonicalizationError::InvalidPercentEncoding
        );
    }

    #[test]
    fn rejects_invalid_percent_decoded_utf8() {
        assert_eq!(
            canonicalize_uri("/%ff").unwrap_err(),
            CanonicalizationError::InvalidUtf8
        );
    }

    #[test]
    fn rejects_newline_smuggling_material() {
        assert_eq!(
            canonicalize_uri("/ok%0d%0aX-Test:1").unwrap_err(),
            CanonicalizationError::ControlCharacter
        );
    }
}
