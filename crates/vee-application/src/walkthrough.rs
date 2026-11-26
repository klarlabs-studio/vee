//! A pull request walkthrough in Vee's summary comment (ADR 0032): the risk
//! tier, a graph of what the change reaches, and a drafted description.
//!
//! The graph comes from impact analysis and labels each edge with how it was
//! found. The description is generated text, marked as unverified. Nothing
//! here reaches the gate.

use crate::{ChangeRisk, ImpactAssessment};
use std::collections::BTreeMap;

/// Edges drawn; more make the graph unreadable.
const MAX_EDGES: usize = 40;

/// Edge certainties found by parsing or a language server, as opposed to
/// name matching or history.
fn measured(certainty: &str) -> bool {
    matches!(
        certainty,
        "resolved_semantic" | "inferred_syntax" | "inferred_import"
    )
}

/// A Mermaid label: quoted, with quotes and markup neutralized.
fn label(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|character| match character {
            '"' => '\'',
            '<' | '>' | '`' | '\n' | '\r' => ' ',
            other => other,
        })
        .collect();
    format!("\"{cleaned}\"")
}

/// The changed files and what they reach, as a Mermaid flowchart, or `None`
/// when impact analysis found no edges.
pub fn impact_graph(impact: &ImpactAssessment) -> Option<String> {
    // One edge per pair, keeping the strongest certainty and the relationships.
    let mut edges: BTreeMap<(&str, &str), (bool, Vec<&str>)> = BTreeMap::new();
    for edge in &impact.paths {
        if edge.source_path == edge.affected_path {
            continue;
        }
        let entry = edges
            .entry((edge.source_path.as_str(), edge.affected_path.as_str()))
            .or_insert((false, Vec::new()));
        entry.0 |= measured(&edge.certainty);
        if !entry.1.contains(&edge.relationship.as_str()) {
            entry.1.push(edge.relationship.as_str());
        }
    }
    if edges.is_empty() {
        return None;
    }
    let total = edges.len();
    // Measured edges first, so a truncated graph keeps the firmest ones.
    let mut ordered: Vec<_> = edges.into_iter().collect();
    ordered.sort_by(
        |(left_key, (left_measured, _)), (right_key, (right_measured, _))| {
            right_measured
                .cmp(left_measured)
                .then_with(|| left_key.cmp(right_key))
        },
    );
    ordered.truncate(MAX_EDGES);
    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    let mut lines = vec!["flowchart LR".to_owned()];
    let mut node = |path: &str, lines: &mut Vec<String>, changed: bool| -> String {
        if let Some(id) = ids.get(path) {
            return id.clone();
        }
        let id = format!("n{}", ids.len());
        lines.push(format!("  {id}[{}]", label(path)));
        if changed {
            lines.push(format!("  class {id} changed"));
        }
        ids.insert(path.to_owned(), id.clone());
        id
    };
    let changed = |path: &str| impact.changed_paths.iter().any(|changed| changed == path);
    for ((source, affected), (is_measured, relationships)) in &ordered {
        let from = node(source, &mut lines, changed(source));
        let to = node(affected, &mut lines, changed(affected));
        let text = format!(
            "{} · {}",
            relationships.join(", "),
            if *is_measured {
                "measured"
            } else {
                "heuristic"
            }
        );
        let arrow = if *is_measured { "-->" } else { "-.->" };
        lines.push(format!("  {from} {arrow}|{}| {to}", label(&text)));
    }
    lines.push("  classDef changed stroke-width:3px".to_owned());
    let mut graph = format!("```mermaid\n{}\n```\n", lines.join("\n"));
    if total > MAX_EDGES {
        graph.push_str(&format!(
            "\n_{} more relationships are not drawn; `vee impact` lists them all._\n",
            total - MAX_EDGES
        ));
    }
    Some(graph)
}

/// The walkthrough section, at most `budget` characters, or `None` when
/// nothing fits.
pub fn section(
    draft: Option<&serde_json::Value>,
    risk: Option<&ChangeRisk>,
    impact: &ImpactAssessment,
    budget: usize,
) -> Option<String> {
    let mut parts = vec!["### Walkthrough".to_owned()];
    if let Some(risk) = risk {
        let flagged: Vec<String> = risk
            .factors
            .iter()
            .filter(|factor| factor.flagged)
            .map(|factor| factor.label.clone())
            .collect();
        parts.push(if flagged.is_empty() {
            format!("**Risk:** {}.", risk.tier.as_str())
        } else {
            format!("**Risk:** {} ({}).", risk.tier.as_str(), flagged.join(", "))
        });
    }
    if let Some(graph) = impact_graph(impact) {
        let coverage = if impact.coverage_complete {
            ""
        } else {
            " Coverage is incomplete, so the change may reach more than this."
        };
        parts.push(format!(
            "**What the change reaches.** Changed files have a bold border. Solid edges were measured by parsing or a language server; dotted edges are heuristic (name matches, packages or history).{coverage}\n\n{graph}"
        ));
    }
    if let Some(draft) = draft {
        let title = draft.get("title").and_then(serde_json::Value::as_str);
        let body = draft.get("body").and_then(serde_json::Value::as_str);
        if let (Some(title), Some(body)) = (title, body) {
            let neutral = |text: &str| text.replace("<!-- vee:", "&lt;!-- vee:");
            parts.push(format!(
                "<details><summary>Drafted description: {}</summary>\n\n_Generated by the reviewer's model from the change; unverified, and never part of the gate._\n\n{}\n\n</details>",
                neutral(title).replace(['<', '>'], ""),
                neutral(body)
            ));
        }
    }
    if parts.len() == 1 {
        return None;
    }
    // Drop the description, then the graph, until it fits.
    while parts.len() > 1 {
        let text = parts.join("\n\n");
        if text.chars().count() <= budget {
            return Some(text);
        }
        parts.pop();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ImpactEdge;

    fn edge(source: &str, affected: &str, relationship: &str, certainty: &str) -> ImpactEdge {
        ImpactEdge {
            source_path: source.into(),
            affected_path: affected.into(),
            relationship: relationship.into(),
            symbol: "s".into(),
            certainty: certainty.into(),
            evidence_line: 1,
            co_change: None,
        }
    }

    fn impact(paths: Vec<ImpactEdge>) -> ImpactAssessment {
        ImpactAssessment {
            schema_version: 4,
            snapshot_id: "s".into(),
            coverage_complete: true,
            analyzers: vec![],
            changed_paths: vec!["src/lib.rs".into()],
            changed_symbols: vec![],
            groups: vec![],
            paths,
            limitations: vec![],
        }
    }

    #[test]
    fn the_graph_labels_measured_and_heuristic_edges() {
        let graph = impact_graph(&impact(vec![
            edge("src/lib.rs", "src/api.rs", "call", "resolved_semantic"),
            edge("src/lib.rs", "src/api.rs", "import", "inferred_heuristic"),
            edge("src/lib.rs", "schemas/a\".json", "co_change", "historical"),
        ]))
        .unwrap();
        assert!(graph.starts_with("```mermaid\nflowchart LR\n"), "{graph}");
        assert!(
            graph.contains("n0 -->|\"call, import · measured\"| n1"),
            "{graph}"
        );
        assert!(graph.contains("-.->|\"co_change · heuristic\"|"), "{graph}");
        assert!(graph.contains("[\"schemas/a'.json\"]"), "{graph}");
        assert!(graph.contains("class n0 changed"), "{graph}");
        assert_eq!(impact_graph(&impact(vec![])), None);
    }

    #[test]
    fn the_section_drops_parts_until_it_fits() {
        let impact = impact(vec![edge(
            "src/lib.rs",
            "src/api.rs",
            "call",
            "resolved_semantic",
        )]);
        let draft = serde_json::json!({"title": "Add <b>caching</b>", "body": "x".repeat(2000)});
        let full = section(Some(&draft), None, &impact, 10_000).unwrap();
        assert!(
            full.contains("Drafted description: Add bcaching/b"),
            "{full}"
        );
        assert!(full.contains("```mermaid"));
        let small = section(Some(&draft), None, &impact, 1_000).unwrap();
        assert!(!small.contains("Drafted description"));
        assert!(small.contains("```mermaid"));
        assert_eq!(section(Some(&draft), None, &impact, 10), None);
        assert_eq!(
            section(None, None, &super::tests::impact(vec![]), 10_000),
            None
        );
    }
}
