use std::collections::BTreeSet;

use aisoc_contracts::schema::{generated_schemas, is_safe_schema_filename, SCHEMA_FILENAMES};
use serde_json::Value;

fn assert_fixed_objects_reject_unknown_fields(value: &Value, location: &str) {
    match value {
        Value::Object(object) => {
            if matches!(
                object.get("properties"),
                Some(Value::Object(properties)) if !properties.is_empty()
            ) {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "fixed object schema must reject unknown fields: {location}"
                );
            }

            for (key, nested) in object {
                assert_fixed_objects_reject_unknown_fields(nested, &format!("{location}/{key}"));
            }
        }
        Value::Array(items) => {
            for (index, nested) in items.iter().enumerate() {
                assert_fixed_objects_reject_unknown_fields(nested, &format!("{location}/{index}"));
            }
        }
        _ => {}
    }
}

#[test]
fn schema_manifest_matches_generated_contracts_exactly() {
    let manifest: BTreeSet<_> = SCHEMA_FILENAMES.iter().copied().collect();
    let generated_contracts = generated_schemas();
    let generated: BTreeSet<_> = generated_contracts
        .iter()
        .map(|(filename, _)| filename)
        .copied()
        .collect();

    assert_eq!(manifest.len(), SCHEMA_FILENAMES.len(), "duplicate schema filename");
    assert_eq!(
        generated.len(),
        generated_contracts.len(),
        "duplicate generated schema filename"
    );
    assert_eq!(manifest, generated, "schema manifest and generator drifted");
}

#[test]
fn every_schema_filename_is_versioned_and_json() {
    for filename in SCHEMA_FILENAMES {
        assert!(
            is_safe_schema_filename(filename),
            "schema filename must be a safe lowercase ASCII basename: {filename}"
        );
    }

    for invalid in [
        "../incident-v1.schema.json",
        "nested/incident-v1.schema.json",
        "Incident-v1.schema.json",
        "-incident-v1.schema.json",
        "incident--v1.schema.json",
        "incident-v2.schema.json",
        "incident.extra-v1.schema.json",
    ] {
        assert!(
            !is_safe_schema_filename(invalid),
            "unsafe schema filename was accepted: {invalid}"
        );
    }
}

#[test]
fn generated_schemas_reject_unknown_fields_at_every_fixed_object_boundary() {
    for (filename, schema) in generated_schemas() {
        let document = serde_json::to_value(schema).expect("serializable generated Schema");
        assert_fixed_objects_reject_unknown_fields(&document, filename);
    }
}
