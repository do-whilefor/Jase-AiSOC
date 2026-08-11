#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfInfo {
    pub architecture: Option<String>,
    pub format: String,
    pub warnings: Vec<&'static str>,
}

pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let size = data.len() as f64;
    let value = counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let probability = count as f64 / size;
            -probability * probability.log2()
        })
        .sum::<f64>();
    (value * 1_000_000.0).round() / 1_000_000.0
}

pub fn ascii_strings(
    data: &[u8],
    minimum_length: usize,
    max_strings: usize,
    max_string_length: usize,
) -> Vec<String> {
    if minimum_length == 0 || max_strings == 0 || max_string_length < minimum_length {
        return Vec::new();
    }

    let mut results = Vec::with_capacity(max_strings.min(128));
    let mut current = Vec::with_capacity(max_string_length.min(256));

    let flush = |current: &mut Vec<u8>, results: &mut Vec<String>| {
        if current.len() >= minimum_length && results.len() < max_strings {
            let bounded = &current[..current.len().min(max_string_length)];
            if let Ok(value) = std::str::from_utf8(bounded) {
                results.push(value.to_owned());
            }
        }
        current.clear();
    };

    for &byte in data {
        if (0x20..=0x7e).contains(&byte) {
            if current.len() < max_string_length {
                current.push(byte);
            }
        } else {
            flush(&mut current, &mut results);
            if results.len() >= max_strings {
                break;
            }
        }
    }
    if results.len() < max_strings {
        flush(&mut current, &mut results);
    }
    results
}

pub fn inspect_elf(data: &[u8]) -> Option<ElfInfo> {
    if data.len() < 4 || &data[..4] != b"\x7fELF" {
        return None;
    }
    if data.len() < 20 {
        return Some(ElfInfo {
            architecture: None,
            format: String::new(),
            warnings: vec!["truncated_elf_header"],
        });
    }

    let class = data[4];
    let byte_order = data[5];
    let mut warnings = Vec::new();
    if !matches!(class, 1 | 2) {
        warnings.push("invalid_elf_class");
    }
    if !matches!(byte_order, 1 | 2) {
        warnings.push("invalid_elf_byte_order");
        return Some(ElfInfo {
            architecture: None,
            format: String::new(),
            warnings,
        });
    }

    let machine = if byte_order == 1 {
        u16::from_le_bytes([data[18], data[19]])
    } else {
        u16::from_be_bytes([data[18], data[19]])
    };
    let architecture = match machine {
        0x03 => "x86".to_owned(),
        0x08 => "mips".to_owned(),
        0x14 => "powerpc".to_owned(),
        0x28 => "arm".to_owned(),
        0x3e => "x86_64".to_owned(),
        0xb7 => "aarch64".to_owned(),
        0xf3 => "riscv".to_owned(),
        other => format!("elf-machine-{other}"),
    };
    let bits = match class {
        1 => "32",
        2 => "64",
        _ => "unknown",
    };
    let endian = if byte_order == 1 { "little" } else { "big" };
    let minimum = if class == 1 { 52 } else { 64 };
    if data.len() < minimum {
        warnings.push("truncated_elf_header");
    }

    Some(ElfInfo {
        architecture: Some(architecture),
        format: format!("ELF{bits} {endian}-endian"),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_is_bounded() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[0_u8; 16]), 0.0);
        assert!((entropy(&(0_u8..=255).collect::<Vec<_>>()) - 8.0).abs() < 0.000001);
    }

    #[test]
    fn strings_are_bounded() {
        let strings = ascii_strings(b"one\0four\0abcdefghij", 4, 2, 6);
        assert_eq!(strings, vec!["four".to_owned(), "abcdef".to_owned()]);
    }

    #[test]
    fn reads_x86_64_elf_header() {
        let mut data = vec![0_u8; 64];
        data[..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        data[18..20].copy_from_slice(&0x3e_u16.to_le_bytes());
        let info = inspect_elf(&data).expect("ELF header");
        assert_eq!(info.architecture.as_deref(), Some("x86_64"));
        assert_eq!(info.format, "ELF64 little-endian");
        assert!(info.warnings.is_empty());
    }
}
