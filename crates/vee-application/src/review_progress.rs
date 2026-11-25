//! Live progress of a review run, reported as each reviewer run finishes.
//!
//! A reviewer with sampling runs several times; each provider execution or
//! provider-cache hit is one run. Progress is observational only: it never
//! affects findings, the gate, or the saved review.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Progress of every reviewer whose provider runs in this review.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewProgress {
    pub reviewers: Vec<ReviewerProgress>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewerProgress {
    pub reviewer_id: String,
    /// Provider runs this reviewer needs (its sample count).
    pub runs: u32,
    /// Runs that have finished, including failed and cached ones.
    pub finished: u32,
    /// Finished runs whose provider failed to execute or exited non-zero.
    /// A run whose output is later rejected as invalid is not counted here;
    /// the saved review's reviewer outcome is authoritative.
    pub failed: u32,
    /// Finished runs answered from the provider cache.
    pub cached: u32,
}

impl ReviewProgress {
    /// Finished and total runs across every reviewer.
    pub fn counts(&self) -> (u32, u32) {
        self.reviewers
            .iter()
            .fold((0, 0), |(done, total), reviewer| {
                (
                    done + reviewer.finished.min(reviewer.runs),
                    total + reviewer.runs,
                )
            })
    }

    /// One line both transports show while a review runs, such as
    /// `3 of 8 reviewer runs finished · running: correctness, security · failed: docs`.
    pub fn summary(&self) -> String {
        let (done, total) = self.counts();
        let mut line = format!("{done} of {total} reviewer runs finished");
        let names = |keep: &dyn Fn(&ReviewerProgress) -> bool| {
            self.reviewers
                .iter()
                .filter(|reviewer| keep(reviewer))
                .map(|reviewer| reviewer.reviewer_id.as_str())
                .collect::<Vec<_>>()
        };
        let running = names(&|reviewer| !reviewer.is_finished());
        if !running.is_empty() {
            line.push_str(&format!(" · running: {}", running.join(", ")));
        }
        let failed = names(&|reviewer| reviewer.failed > 0);
        if !failed.is_empty() {
            line.push_str(&format!(" · failed: {}", failed.join(", ")));
        }
        line
    }
}

impl ReviewerProgress {
    pub fn is_finished(&self) -> bool {
        self.finished >= self.runs
    }
}

/// Receives a progress snapshot when execution starts and after each run.
/// Called from provider worker threads; implementations must be cheap.
pub trait ReviewProgressSink: Send + Sync {
    fn report(&self, progress: &ReviewProgress);
}

/// Tracks runs by their position in the prepared-run list.
pub(crate) struct ProgressTracker<'a> {
    sink: Option<&'a dyn ReviewProgressSink>,
    /// Reviewer slot for each prepared run.
    slots: Vec<usize>,
    state: Mutex<ReviewProgress>,
}

impl<'a> ProgressTracker<'a> {
    /// `runs` yields each prepared run's reviewer ID, in prepared order.
    pub(crate) fn new<'r>(
        sink: Option<&'a dyn ReviewProgressSink>,
        runs: impl IntoIterator<Item = &'r str>,
    ) -> Self {
        let mut progress = ReviewProgress::default();
        let mut slots = Vec::new();
        for reviewer_id in runs {
            let slot = match progress
                .reviewers
                .iter()
                .position(|reviewer| reviewer.reviewer_id == reviewer_id)
            {
                Some(slot) => slot,
                None => {
                    progress.reviewers.push(ReviewerProgress {
                        reviewer_id: reviewer_id.to_owned(),
                        runs: 0,
                        finished: 0,
                        failed: 0,
                        cached: 0,
                    });
                    progress.reviewers.len() - 1
                }
            };
            progress.reviewers[slot].runs += 1;
            slots.push(slot);
        }
        Self {
            sink,
            slots,
            state: Mutex::new(progress),
        }
    }

    pub(crate) fn mark_cached(&self, run: usize) {
        self.update(run, |reviewer| reviewer.cached += 1, false);
    }

    pub(crate) fn mark_finished(&self, run: usize, succeeded: bool) {
        self.update(
            run,
            |reviewer| {
                if !succeeded {
                    reviewer.failed += 1;
                }
            },
            true,
        );
    }

    /// Report the current snapshot without changing it.
    pub(crate) fn report(&self) {
        if let Some(sink) = self.sink {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            sink.report(&state);
        }
    }

    fn update(&self, run: usize, change: impl FnOnce(&mut ReviewerProgress), report: bool) {
        let Some(&slot) = self.slots.get(run) else {
            return;
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let reviewer = &mut state.reviewers[slot];
        reviewer.finished += 1;
        change(reviewer);
        if report {
            if let Some(sink) = self.sink {
                sink.report(&state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewer(id: &str, runs: u32, finished: u32, failed: u32) -> ReviewerProgress {
        ReviewerProgress {
            reviewer_id: id.into(),
            runs,
            finished,
            failed,
            cached: 0,
        }
    }

    #[test]
    fn the_summary_counts_runs_and_names_running_and_failed_reviewers() {
        let progress = ReviewProgress {
            reviewers: vec![
                reviewer("correctness", 2, 1, 0),
                reviewer("security", 1, 0, 0),
                reviewer("docs", 1, 1, 1),
            ],
        };
        assert_eq!(progress.counts(), (2, 4));
        assert_eq!(
            progress.summary(),
            "2 of 4 reviewer runs finished · running: correctness, security · failed: docs"
        );
        let done = ReviewProgress {
            reviewers: vec![reviewer("correctness", 1, 1, 0)],
        };
        assert_eq!(done.summary(), "1 of 1 reviewer runs finished");
    }
}
