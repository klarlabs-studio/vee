//! Views for patch proposals.

use crate::view::{Cell, ToView, Tone, View};
use vee_application::operations::{PatchApplication, PatchProposal};

impl ToView for PatchProposal {
    fn to_view(&self) -> View {
        let view = View::new()
            .title(
                format!("Patch proposal for review {}", self.review_id),
                Some(if self.validated {
                    Cell::badge(Tone::Success, "validated")
                } else {
                    Cell::badge(Tone::Danger, "not validated")
                }),
            )
            .fields(vec![
                ("Patch".into(), Cell::id(&self.patch_digest)),
                (
                    "Size".into(),
                    Cell::plain(format!("{} bytes", self.patch_bytes)),
                ),
                ("Snapshot".into(), Cell::code(&self.snapshot_id)),
                ("Saved at".into(), Cell::code(&self.patch_path)),
                ("Application".into(), Cell::plain(&self.application)),
            ])
            .section(format!("Files ({})", self.patch_inputs.len()));
        let view = if self.patch_inputs.is_empty() {
            view.paragraph(Cell::muted("The patch touches no tracked files."))
        } else {
            view.table(
                &["Path", "Status"],
                self.patch_inputs
                    .iter()
                    .map(|file| vec![Cell::code(&file.path), Cell::plain(&file.status)])
                    .collect(),
            )
        };
        view.note(Tone::Info, "No repository files were changed.")
            .paragraph(Cell::plain(&self.approval_instruction))
            .next_step(format!(
                "vee findings apply-patch {digest} --approve {digest}",
                digest = self.patch_digest
            ))
    }
}

impl ToView for PatchApplication {
    fn to_view(&self) -> View {
        let mut view = View::new()
            .title(
                "Patch applied",
                Some(if self.concurrent_mutation_detected {
                    Cell::badge(Tone::Warning, "target changed concurrently")
                } else {
                    Cell::badge(Tone::Success, &self.application)
                }),
            )
            .fields(vec![("Patch".into(), Cell::id(&self.proposal_digest))]);
        if self.concurrent_mutation_detected {
            view = view.note(
                Tone::Warning,
                "Files changed while the patch was applied; inspect the follow-up review.",
            );
        }
        view.extend(self.review.to_view())
    }
}
