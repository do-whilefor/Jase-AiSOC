#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;

use aisoc_contracts::schema::{generated_schemas, is_safe_schema_filename, SCHEMA_FILENAMES};

fn main() -> Result<(), String> {
    let mut arguments = env::args_os().skip(1);
    let first = arguments.next();
    let (check_only, output_dir) = if first.as_deref() == Some(std::ffi::OsStr::new("--check")) {
        (
            true,
            arguments
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("schemas")),
        )
    } else {
        (
            false,
            first
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("schemas")),
        )
    };
    if arguments.next().is_some() {
        return Err("usage: aisoc-export-schemas [--check] [output-directory]".to_owned());
    }

    let schemas = generated_schemas();
    let manifest_names: std::collections::BTreeSet<_> =
        SCHEMA_FILENAMES.iter().copied().collect();
    let generated_names: std::collections::BTreeSet<_> =
        schemas.iter().map(|(filename, _)| *filename).collect();
    if manifest_names.len() != SCHEMA_FILENAMES.len() {
        return Err("duplicate schema filename in manifest".to_owned());
    }
    if generated_names.len() != schemas.len() {
        return Err("duplicate generated schema filename".to_owned());
    }
    if manifest_names != generated_names {
        return Err("schema manifest and generator drifted".to_owned());
    }
    if let Some(filename) = generated_names
        .iter()
        .find(|filename| !is_safe_schema_filename(filename))
    {
        return Err(format!("unsafe generated schema filename: {filename}"));
    }

    if check_only && !output_dir.is_dir() {
        return Err(format!(
            "schema drift check directory does not exist: {}",
            output_dir.display()
        ));
    }
    if !check_only {
        fs::create_dir_all(&output_dir).map_err(|error| error.to_string())?;
    }

    for (filename, schema) in &schemas {
        let json = serde_json::to_string_pretty(schema).map_err(|error| error.to_string())?;
        let expected = format!("{json}\n");
        let path = output_dir.join(filename);
        if check_only {
            let committed = fs::read_to_string(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            if committed != expected {
                return Err(format!("schema drift detected: {}", path.display()));
            }
        } else {
            fs::write(&path, expected).map_err(|error| error.to_string())?;
        }
    }

    if check_only {
        for entry in fs::read_dir(&output_dir).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".schema.json") && !generated_names.contains(name.as_str()) {
                return Err(format!("unexpected committed schema: {name}"));
            }
        }
    }
    Ok(())
}
