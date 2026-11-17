use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;
use vero_core::ChangeSet;

pub fn snapshot_context(
    root: &Path,
    change_set: &ChangeSet,
    max_files: usize,
    max_file_bytes: usize,
    max_total_bytes: usize,
) -> Result<Value> {
    let mut files = Vec::new();
    let mut used_bytes = 0usize;
    let mut omitted = 0usize;
    for file in &change_set.files {
        let mut record = json!({
            "path": file.path,
            "status": file.status,
            "mode": file.mode,
            "content_digest": file.content_digest,
            "content": Value::Null,
            "content_omitted": false
        });
        if files.len() >= max_files {
            record["content_omitted"] = Value::Bool(true);
            omitted += 1;
            files.push(record);
            continue;
        }
        let Some(bytes) = vero_git::read_snapshot_file(root, change_set, Path::new(&file.path))
            .map_err(anyhow::Error::msg)?
        else {
            continue;
        };
        let fits = bytes.len() <= max_file_bytes
            && used_bytes.saturating_add(bytes.len()) <= max_total_bytes;
        match String::from_utf8(bytes) {
            Ok(content) if fits => {
                used_bytes = used_bytes.saturating_add(content.len());
                record["content"] = Value::String(content);
            }
            Ok(_) | Err(_) => {
                record["content_omitted"] = Value::Bool(true);
                omitted += 1;
            }
        }
        files.push(record);
    }
    Ok(json!({
        "snapshot_id": change_set.digest,
        "scope": change_set.scope,
        "base_oid": change_set.base_oid,
        "head_oid": change_set.head_oid,
        "context_complete": omitted == 0 && change_set.warnings.is_empty(),
        "omitted_content_file_count": omitted,
        "warnings": change_set.warnings,
        "files": files,
        "classification": "untrusted_repository_snapshot"
    }))
}

pub fn output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "title": {"type": "string", "minLength": 1, "maxLength": 120},
            "body": {"type": "string", "minLength": 1, "maxLength": 12000}
        },
        "required": ["title", "body"],
        "additionalProperties": false
    })
}

pub const INSTRUCTIONS: &str = "Draft a useful pull request title and description from the provided exact change snapshot. Explain the purpose and important behavior changes using only evidence in the supplied snapshot. Do not claim tests passed unless test evidence is explicitly present. Do not invent ticket requirements, risk, compatibility, or deployment facts. If context is incomplete, keep claims limited to included evidence. Use concise Markdown in the body, with Summary, Changes, and Testing sections when supported. This is an unapproved draft, not review evidence or a gate decision.";

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use vero_core::SnapshotFile;

    #[test]
    fn context_is_snapshot_bound_and_marks_truncated_content() {
        let directory = tempdir().unwrap();
        std::fs::write(directory.path().join("lib.rs"), "pub fn changed() {}\n").unwrap();
        let bytes = std::fs::read(directory.path().join("lib.rs")).unwrap();
        let change_set = ChangeSet::from_entries(
            Some("base".into()),
            Some("head".into()),
            "working_tree",
            vec![SnapshotFile {
                path: "lib.rs".into(),
                mode: 0o100644,
                content_digest: vero_core::digest(&bytes),
                status: "modified".into(),
            }],
        );
        let context = snapshot_context(directory.path(), &change_set, 10, 2, 20).unwrap();
        assert_eq!(context["snapshot_id"], change_set.digest);
        assert_eq!(context["context_complete"], false);
        assert_eq!(context["omitted_content_file_count"], 1);
        assert_eq!(context["files"][0]["content_omitted"], true);
        assert!(context["files"][0]["content"].is_null());
    }

    #[test]
    fn generated_content_schema_rejects_additional_fields_by_contract() {
        let schema = output_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"].as_array().unwrap().len(), 2);
    }
}
