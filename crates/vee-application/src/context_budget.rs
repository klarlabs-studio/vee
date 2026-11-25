//! How a reviewer's byte budget is shared across the files of a change.
//!
//! A change's own lines matter more than the unchanged code around them, so
//! every file's bounded diff is reserved before any file is upgraded to full
//! contents. Greedy full-contents-first allocation let a few large files at
//! the start of a change use the whole budget, leaving later files with
//! neither contents nor diff.

/// What one changed text file costs in each representation, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ContextCost {
    /// Baseline plus current contents; `None` when either exceeds the
    /// per-file limit.
    pub full: Option<usize>,
    /// The bounded unified diff; `None` when it could not be built within the
    /// per-file limit.
    pub diff: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContextChoice {
    Full,
    Diff,
    Omit,
}

/// Choose a representation per file, in input order, within `budget` bytes.
///
/// 1. Each file takes its cheapest representation while the budget allows,
///    in order; a file that does not fit is omitted.
/// 2. Leftover budget upgrades diffs to full contents, smallest increase
///    first (ties by input order), so as many files as possible are complete.
///
/// The result is deterministic for the same costs and budget.
pub(crate) fn allocate(costs: &[ContextCost], budget: usize) -> Vec<ContextChoice> {
    let mut used = 0usize;
    let mut choices = costs
        .iter()
        .map(|cost| {
            let cheapest = match (cost.full, cost.diff) {
                (Some(full), Some(diff)) if full <= diff => Some((ContextChoice::Full, full)),
                (_, Some(diff)) => Some((ContextChoice::Diff, diff)),
                (Some(full), None) => Some((ContextChoice::Full, full)),
                (None, None) => None,
            };
            match cheapest {
                Some((choice, bytes)) if used.saturating_add(bytes) <= budget => {
                    used += bytes;
                    choice
                }
                _ => ContextChoice::Omit,
            }
        })
        .collect::<Vec<_>>();
    let mut upgrades = costs
        .iter()
        .enumerate()
        .filter(|(index, _)| choices[*index] == ContextChoice::Diff)
        .filter_map(|(index, cost)| {
            let (full, diff) = (cost.full?, cost.diff?);
            Some((full.saturating_sub(diff), index))
        })
        .collect::<Vec<_>>();
    upgrades.sort_unstable();
    for (extra, index) in upgrades {
        if used.saturating_add(extra) <= budget {
            used += extra;
            choices[index] = ContextChoice::Full;
        }
    }
    choices
}

#[cfg(test)]
mod tests {
    use super::{allocate, ContextChoice::*, ContextCost};

    fn cost(full: Option<usize>, diff: Option<usize>) -> ContextCost {
        ContextCost { full, diff }
    }

    #[test]
    fn everything_fits_in_full() {
        let costs = [cost(Some(10), Some(4)), cost(Some(20), Some(5))];
        assert_eq!(allocate(&costs, 30), vec![Full, Full]);
    }

    #[test]
    fn large_early_files_do_not_starve_later_diffs() {
        // Full-first allocation would spend 90 of 100 bytes on the first
        // file and omit the other two.
        let costs = [
            cost(Some(90), Some(10)),
            cost(Some(40), Some(15)),
            cost(Some(30), Some(20)),
        ];
        let choices = allocate(&costs, 100);
        assert!(!choices.contains(&Omit), "{choices:?}");
        // 45 bytes of diffs leave 55: the cheapest upgrades are file 3 (+10)
        // and file 2 (+25); file 1 (+80) no longer fits.
        assert_eq!(choices, vec![Diff, Full, Full]);
    }

    #[test]
    fn files_beyond_the_budget_are_omitted_in_order() {
        let costs = [
            cost(None, Some(60)),
            cost(None, Some(60)),
            cost(None, Some(30)),
        ];
        assert_eq!(allocate(&costs, 100), vec![Diff, Omit, Diff]);
    }

    #[test]
    fn a_small_new_file_is_sent_in_full_when_that_is_cheaper_than_its_diff() {
        let costs = [cost(Some(8), Some(12)), cost(None, None)];
        assert_eq!(allocate(&costs, 100), vec![Full, Omit]);
    }

    #[test]
    fn upgrade_ties_follow_input_order() {
        let costs = [cost(Some(20), Some(10)), cost(Some(20), Some(10))];
        assert_eq!(allocate(&costs, 30), vec![Full, Diff]);
    }
}
