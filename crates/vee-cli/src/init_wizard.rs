//! Guided `vee init`: in a terminal, ask which backend, model and review effort
//! to use, explaining each recommendation. The guidance itself comes from the
//! detection report, so the CLI, MCP and agents give the same advice.

use std::io::{self, BufRead, Write};
use vee_application::setup::{DetectionReport, MachineSetup};
use vee_core::ReviewEffort;

/// What the person chose; `None` means the default `vee init` would use.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Choices {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub effort: Option<ReviewEffort>,
}

const BEST_RESULTS: &str = vee_present::BEST_RESULTS_GUIDE;

pub(crate) fn ask(
    detection: &DetectionReport,
    machine: &MachineSetup,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> io::Result<Choices> {
    let mut choices = Choices::default();
    if let Some(provider) = &machine.default_provider {
        writeln!(output, "This machine reviews with {provider}.")?;
    } else {
        let available: Vec<_> = detection
            .candidates
            .iter()
            .filter(|candidate| candidate.available)
            .collect();
        if available.is_empty() {
            return Ok(choices);
        }
        writeln!(output, "AI backends found on this machine:")?;
        let default = available
            .iter()
            .position(|candidate| detection.recommended.as_deref() == Some(&candidate.candidate_id))
            .unwrap_or(0);
        let labels: Vec<String> = available
            .iter()
            .map(|candidate| {
                let mut label = format!(
                    "{} ({}, {})",
                    candidate.candidate_id, candidate.kind, candidate.egress
                );
                if candidate.egress == "local" {
                    label.push_str(": source stays on this machine");
                } else if detection
                    .model_suggestions
                    .contains_key(&candidate.candidate_id)
                {
                    label.push_str(": best measured review quality with the recommended model");
                }
                label
            })
            .collect();
        let chosen = available[choose(&labels, default, input, output)?];
        choices.provider = Some(chosen.candidate_id.clone());
        choices.model = ask_model(detection, chosen, input, output)?;
    }

    writeln!(
        output,
        "\nReview effort (how many times each reviewer reviews a change):"
    )?;
    let options = &detection.effort_options;
    let default = machine
        .effort
        .and_then(|effort| options.iter().position(|option| option.effort == effort))
        .or_else(|| options.iter().position(|option| option.recommended))
        .unwrap_or(0);
    let labels: Vec<String> = options
        .iter()
        .map(|option| {
            let marker = if option.recommended {
                ", recommended"
            } else {
                ""
            };
            format!(
                "{} ({} run{}{marker}): {}",
                effort_name(option.effort),
                option.runs,
                if option.runs == 1 { "" } else { "s" },
                option.note
            )
        })
        .collect();
    if !options.is_empty() {
        choices.effort = Some(options[choose(&labels, default, input, output)?].effort);
    }
    writeln!(
        output,
        "\nFor how to get the best results, see {BEST_RESULTS}.\n"
    )?;
    Ok(choices)
}

fn ask_model(
    detection: &DetectionReport,
    candidate: &vee_application::setup::Candidate,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> io::Result<Option<String>> {
    let suggestions = detection
        .model_suggestions
        .get(&candidate.candidate_id)
        .cloned()
        .unwrap_or_default();
    let mut models: Vec<Option<String>> = Vec::new();
    let mut labels = Vec::new();
    for suggestion in &suggestions {
        let marker = if suggestion.recommended {
            ", recommended"
        } else {
            ""
        };
        labels.push(format!("{}{marker}: {}", suggestion.model, suggestion.note));
        models.push(Some(suggestion.model.clone()));
    }
    for model in &candidate.models {
        labels.push(model.clone());
        models.push(Some(model.clone()));
    }
    if !candidate.requires_model && candidate.models.is_empty() {
        labels.push(format!(
            "the model configured in {}",
            candidate.candidate_id
        ));
        models.push(None);
    }
    labels.push("another model: type its name".into());
    let default = suggestions
        .iter()
        .position(|suggestion| suggestion.recommended)
        .unwrap_or(0);
    writeln!(output, "\nModel for {}:", candidate.candidate_id)?;
    let chosen = choose(&labels, default, input, output)?;
    if chosen < models.len() {
        return Ok(models[chosen].clone());
    }
    loop {
        write!(output, "Model name: ")?;
        output.flush()?;
        let line = read_line(input)?;
        if !line.is_empty() {
            return Ok(Some(line));
        }
    }
}

/// Show numbered options and return the chosen index; Enter takes the default.
fn choose(
    labels: &[String],
    default: usize,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> io::Result<usize> {
    for (index, label) in labels.iter().enumerate() {
        writeln!(output, "  {}. {label}", index + 1)?;
    }
    loop {
        write!(output, "Choose 1-{} [{}]: ", labels.len(), default + 1)?;
        output.flush()?;
        let line = read_line(input)?;
        if line.is_empty() {
            return Ok(default);
        }
        match line.parse::<usize>() {
            Ok(number) if (1..=labels.len()).contains(&number) => return Ok(number - 1),
            _ => writeln!(output, "Enter a number from 1 to {}.", labels.len())?,
        }
    }
}

fn read_line(input: &mut impl BufRead) -> io::Result<String> {
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "input ended before setup finished",
        ));
    }
    Ok(line.trim().to_owned())
}

fn effort_name(effort: ReviewEffort) -> &'static str {
    match effort {
        ReviewEffort::Low => "low",
        ReviewEffort::Medium => "medium",
        ReviewEffort::High => "high",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vee_application::setup::{effort_options, model_suggestions, BackendFamily, Candidate};

    fn candidate(id: &str, kind: &str, egress: &str, family: BackendFamily) -> Candidate {
        Candidate {
            candidate_id: id.into(),
            family,
            kind: kind.into(),
            egress: egress.into(),
            available: true,
            detail: None,
            models: Vec::new(),
            requires_model: false,
            reason: None,
        }
    }

    fn detection() -> DetectionReport {
        let mut ollama = candidate(
            "ollama",
            "ollama_native",
            "local",
            BackendFamily::LocalModel,
        );
        ollama.models = vec!["qwen3-coder:30b".into()];
        DetectionReport {
            schema_version: 1,
            candidates: vec![
                ollama,
                candidate("claude", "claude_cli", "network", BackendFamily::AgentCli),
                candidate("codex", "codex_cli", "network", BackendFamily::AgentCli),
            ],
            recommended: Some("ollama".into()),
            model_suggestions: [("claude".to_string(), model_suggestions("claude"))].into(),
            effort_options: effort_options(),
        }
    }

    fn run(machine: MachineSetup, answers: &str) -> (Choices, String) {
        let mut output = Vec::new();
        let choices = ask(&detection(), &machine, &mut answers.as_bytes(), &mut output).unwrap();
        (choices, String::from_utf8(output).unwrap())
    }

    #[test]
    fn enter_takes_every_recommendation() {
        let (choices, output) = run(MachineSetup::default(), "\n\n\n");
        assert_eq!(choices.provider.as_deref(), Some("ollama"));
        assert_eq!(choices.model.as_deref(), Some("qwen3-coder:30b"));
        assert_eq!(choices.effort, Some(ReviewEffort::Medium));
        assert!(output.contains("source stays on this machine"));
        assert!(output.contains("best-results.md"));
    }

    #[test]
    fn choosing_claude_offers_its_models_with_reasons() {
        let (choices, output) = run(MachineSetup::default(), "2\n\n3\n");
        assert_eq!(choices.provider.as_deref(), Some("claude"));
        assert_eq!(choices.model.as_deref(), Some("claude-opus-5-5"));
        assert_eq!(choices.effort, Some(ReviewEffort::High));
        assert!(output.contains("claude-opus-5-5, recommended: Finds the most defects"));
    }

    #[test]
    fn a_cli_can_keep_its_own_model_or_take_a_typed_one() {
        let (choices, _) = run(MachineSetup::default(), "3\n1\n1\n");
        assert_eq!(choices.provider.as_deref(), Some("codex"));
        assert_eq!(choices.model, None);
        let (choices, _) = run(MachineSetup::default(), "3\n2\ngpt-custom\n1\n");
        assert_eq!(choices.model.as_deref(), Some("gpt-custom"));
        assert_eq!(choices.effort, Some(ReviewEffort::Low));
    }

    #[test]
    fn invalid_answers_are_asked_again() {
        let (choices, output) = run(MachineSetup::default(), "9\nx\n2\n\n\n");
        assert_eq!(choices.provider.as_deref(), Some("claude"));
        assert_eq!(output.matches("Enter a number from 1 to 3.").count(), 2);
    }

    #[test]
    fn a_configured_machine_is_only_asked_for_effort_starting_from_its_current_one() {
        let machine = MachineSetup {
            default_provider: Some("claude_cli claude-opus-5-5".into()),
            effort: Some(ReviewEffort::High),
        };
        let (choices, output) = run(machine, "\n");
        assert_eq!(choices.provider, None);
        assert_eq!(choices.model, None);
        assert_eq!(choices.effort, Some(ReviewEffort::High));
        assert!(output.contains("This machine reviews with claude_cli claude-opus-5-5."));
        assert!(output.contains("[3]"));
    }

    #[test]
    fn closed_input_stops_setup_instead_of_looping() {
        let mut output = Vec::new();
        let error = ask(
            &detection(),
            &MachineSetup::default(),
            &mut "".as_bytes(),
            &mut output,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
