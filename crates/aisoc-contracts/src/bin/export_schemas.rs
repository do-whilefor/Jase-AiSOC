#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;

use aisoc_contracts::schema::generated_schemas;

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

    if check_only && !output_dir.is_dir() {
        return Err(format!(
            "schema drift check directory does not exist: {}",
            output_dir.display()
        ));
    }
    if !check_only {
        fs::create_dir_all(&output_dir).map_err(|error| error.to_string())?;
    }

    for (filename, schema) in generated_schemas() {
        let json = serde_json::to_string_pretty(&schema).map_err(|error| error.to_string())?;
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
        let expected_names: std::collections::BTreeSet<_> = generated_schemas()
            .into_iter()
            .map(|(filename, _)| filename.to_owned())
            .collect();
        for entry in fs::read_dir(&output_dir).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".schema.json") && !expected_names.contains(&name) {
                return Err(format!("unexpected committed schema: {name}"));
            }
        }
    }
    Ok(())
}
