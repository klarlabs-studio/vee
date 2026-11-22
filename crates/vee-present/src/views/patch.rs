//! Views for patch proposals.

use crate::view::{Cell, ToView, Tone, View};
use vee_application::operations::PatchProposal;

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
