use std::collections::BTreeSet;

use aisoc_contracts::schema::{generated_schemas, SCHEMA_FILENAMES};
use schemars::schema::Schema;

#[test]
fn schema_manifest_matches_generated_contracts_exactly() {
    let manifest: BTreeSet<_> = SCHEMA_FILENAMES.iter().copied().collect();
    let generated: BTreeSet<_> = generated_schemas()
        .into_iter()
        .map(|(filename, _)| filename)
        .collect();

    assert_eq!(manifest.len(), SCHEMA_FILENAMES.len(), "duplicate schema filename");
    assert_eq!(manifest, generated, "schema manifest and generator drifted");
}

#[test]
fn every_schema_filename_is_versioned_and_json() {
    for filename in SCHEMA_FILENAMES {
        assert!(filename.ends_with("-v1.schema.json"), "unversioned schema: {filename}");
    }
}

#[test]
fn generated_schemas_reject_additional_properties_at_contract_roots() {
    for (filename, schema) in generated_schemas() {
        let root = schema.schema.object.as_ref().expect("object contract root");
        assert!(
            matches!(root.additional_properties.as_deref(), Some(Schema::Bool(false))),
            "root contract must reject unknown fields: {filename}"
        );
    }
}
