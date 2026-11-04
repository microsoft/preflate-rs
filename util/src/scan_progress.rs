use std::time::{Duration, Instant};

use crate::Summary;

const INTERVAL: Duration = Duration::from_secs(2);

pub struct Progress {
    total: Option<u64>,
    last_update: Instant,
    last_entries: u64,
}

impl Progress {
    pub fn new(total: Option<u64>) -> Self {
        match total {
            Some(total) => eprintln!("Scanning {total} files..."),
            None => eprintln!("Scanning files..."),
        }
        Self {
            total,
            last_update: Instant::now(),
            last_entries: 0,
        }
    }

    fn due(&mut self, entries: u64, now: Instant, finished: bool) -> bool {
        if entries == self.last_entries
            || (!finished && now.duration_since(self.last_update) < INTERVAL)
        {
            return false;
        }
        self.last_entries = entries;
        self.last_update = now;
        true
    }

    pub fn update(&mut self, summary: &Summary, finished: bool) {
        if !self.due(summary.entries, Instant::now(), finished) {
            return;
        }
        let files = match self.total {
            Some(total) if total != 0 => format!(
                "{}/{} files ({:.1}%)",
                summary.entries,
                total,
                summary.entries as f64 * 100.0 / total as f64
            ),
            _ => format!("{} files", summary.entries),
        };
        eprintln!(
            "Progress: {files} | {} verified streams, {} failed candidates, {} file errors",
            summary.verified_streams,
            summary.failed_candidates,
            summary.filesystem_errors + summary.panicked_files,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_is_rate_limited_but_always_finishes_without_duplicate_updates() {
        let start = Instant::now();
        let mut progress = Progress {
            total: Some(100),
            last_update: start,
            last_entries: 0,
        };
        assert!(!progress.due(1, start + Duration::from_secs(1), false));
        assert!(progress.due(50, start + INTERVAL, false));
        assert!(!progress.due(75, start + INTERVAL + Duration::from_secs(1), false));
        assert!(progress.due(100, start + INTERVAL + Duration::from_secs(1), true));
        assert!(!progress.due(100, start + INTERVAL * 2, true));
    }
}
