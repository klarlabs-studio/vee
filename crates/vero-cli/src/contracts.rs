//! Published JSON Schema contracts, embedded at build time.
//!
//! The files under `schemas/` are the single definition of every machine-readable
//! Vero document. The CLI emits these documents for `--output json`, and the MCP
//! server declares the same schemas as tool `outputSchema`s, so both transports are
//! held to one contract.

use serde_json::{Map, Value};

macro_rules! schemas {
    ($($name:literal),* $(,)?) => {
        &[$(($name, include_str!(concat!("../../../schemas/", $name, ".schema.json")))),*]
    };
}

const SCHEMAS: &[(&str, &str)] = schemas![
    "acceptance-traceability-v1",
    "cross-repository-impact-v16",
    "doctor-report-v1",
    "evidence-v1",
    "finding-detail-v2",
    "finding-feedback-v1",
    "finding-status-update-v1",
    "finding-task-v3",
    "finding-work-package-v2",
    "findings-list-v2",
    "gate-check-v1",
    "gate-decision-v1",
    "impact-assessment-v3",
    "init-report-v1",
    "imported-review-search-v3",
    "provider-detection-v1",
    "quality-analytics-v9",
    "review-output-v2",
    "rule-candidates-v3",
    "rule-effectiveness-v1",
    "standards-resolution-v1",
    "verification-diagnosis-v2",
    "verification-run-v1",
    "waiver-v1",
    "work-item-v1",
];

const SCHEMA_SUFFIX: &str = ".schema.json";

fn parse(name: &str) -> Value {
    let (_, text) = SCHEMAS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .unwrap_or_else(|| panic!("schema {name} is not embedded"));
    serde_json::from_str(text).unwrap_or_else(|error| panic!("schema {name} is invalid: {error}"))
}

fn external_references(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            if let Some(Value::String(reference)) = object.get("$ref") {
                let document = reference.split('#').next().unwrap_or_default();
                if let Some(name) = document.strip_suffix(SCHEMA_SUFFIX) {
                    found.push(name.to_owned());
                }
            }
            object
                .values()
                .for_each(|child| external_references(child, found));
        }
        Value::Array(items) => items
            .iter()
            .for_each(|child| external_references(child, found)),
        _ => {}
    }
}

/// Return a self-contained schema: every externally referenced schema document is
/// embedded under `$defs` with its own `$id`, the JSON Schema 2020-12 compound
/// document form. Relative `$ref`s then resolve against the embedded `$id`s.
pub fn bundled(name: &str) -> Value {
    let mut root = parse(name);
    let mut pending = Vec::new();
    external_references(&root, &mut pending);
    let mut embedded = Map::new();
    while let Some(dependency) = pending.pop() {
        let key = format!("{dependency}{SCHEMA_SUFFIX}");
        if dependency == name || embedded.contains_key(&key) {
            continue;
        }
        let mut document = parse(&dependency);
        external_references(&document, &mut pending);
        if let Value::Object(object) = &mut document {
            object.remove("$schema");
        }
        embedded.insert(key, document);
    }
    if !embedded.is_empty() {
        let definitions = root
            .as_object_mut()
            .expect("schema root is an object")
            .entry("$defs")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("$defs is an object");
        definitions.extend(embedded);
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_embedded_schema_bundles_into_an_offline_validator() {
        for (name, _) in SCHEMAS {
            let schema = bundled(name);
            jsonschema::options()
                .offline()
                .build(&schema)
                .unwrap_or_else(|error| panic!("{name} does not compile offline: {error}"));
        }
    }

    #[test]
    fn bundling_is_what_resolves_external_references() {
        let unbundled = parse("review-output-v2");
        assert!(
            jsonschema::options().offline().build(&unbundled).is_err(),
            "fixture should depend on external schema documents"
        );
        let schema = bundled("review-output-v2");
        assert!(schema["$defs"]["gate-decision-v1.schema.json"].is_object());
        assert!(jsonschema::options().offline().build(&schema).is_ok());
    }
}
