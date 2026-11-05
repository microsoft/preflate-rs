//! Bounded parallel file inspection with deterministic result ordering.
//!
//! A fixed worker pool inspects files independently and tags each result with its
//! submission order. The coordinator holds out-of-order results until the next
//! expected result arrives, then passes them to the report writer in input order.
//!
//! Submission is throttled by the number of results not yet emitted, bounding
//! both queued work and completed results behind a slow file. Worker panics
//! become file failures, and shutdown drops the queues and joins workers so a
//! writer error does not leave blocked background work behind.

use std::{
    collections::BTreeMap,
    fs::Metadata,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    thread,
};

use crate::{Cli, FileReport, Result};

pub enum Task {
    File(PathBuf, Metadata),
    Ready(FileReport),
    #[cfg(test)]
    Probe(PathBuf, Box<dyn FnOnce() -> FileReport + Send>),
}

impl Task {
    pub fn path(&self) -> &Path {
        match self {
            Self::File(path, _) => path,
            Self::Ready(report) => &report.path,
            #[cfg(test)]
            Self::Probe(path, _) => path,
        }
    }

    pub fn inspect(self, cli: &Cli) -> FileReport {
        match self {
            Self::File(path, metadata) => crate::inspect_file(path, &metadata, cli),
            Self::Ready(report) => report,
            #[cfg(test)]
            Self::Probe(_, inspect) => inspect(),
        }
    }
}

struct Job {
    ordinal: u64,
    path: PathBuf,
    task: Task,
}

struct Completed {
    ordinal: u64,
    path: PathBuf,
    report: FileReport,
}

type Emit<'a> = dyn FnMut(&Path, FileReport) -> Result<()> + 'a;

pub struct Pool<'a> {
    sender: mpsc::SyncSender<Job>,
    receiver: mpsc::Receiver<Completed>,
    pending: BTreeMap<u64, Completed>,
    submitted: u64,
    emitted: u64,
    capacity: u64,
    emit: &'a mut Emit<'a>,
}

impl Pool<'_> {
    pub fn submit(&mut self, path: PathBuf, task: Task) -> Result<()> {
        if self.submitted - self.emitted >= self.capacity {
            self.emit_next()?;
        }
        self.sender.send(Job {
            ordinal: self.submitted,
            path,
            task,
        })?;
        self.submitted += 1;
        Ok(())
    }

    fn emit_next(&mut self) -> Result<()> {
        while !self.pending.contains_key(&self.emitted) {
            let completed = self.receiver.recv()?;
            if self.pending.insert(completed.ordinal, completed).is_some() {
                return Err("duplicate file result from scan worker".into());
            }
        }
        let completed = self
            .pending
            .remove(&self.emitted)
            .ok_or("missing ordered file result")?;
        (self.emit)(&completed.path, completed.report)?;
        self.emitted += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        while self.emitted < self.submitted {
            self.emit_next()?;
        }
        Ok(())
    }
}

pub fn run(
    cli: &Cli,
    produce: impl FnOnce(&mut Pool<'_>) -> Result<()>,
    mut emit: impl FnMut(&Path, FileReport) -> Result<()>,
) -> Result<()> {
    let jobs = cli.worker_count();
    let (sender, receiver) = mpsc::sync_channel::<Job>(jobs);
    let receiver = Arc::new(Mutex::new(receiver));
    let (completed, results) = mpsc::sync_channel(jobs);
    thread::scope(|scope| {
        let mut workers = Vec::with_capacity(jobs);
        for _ in 0..jobs {
            let receiver = Arc::clone(&receiver);
            let completed = completed.clone();
            workers.push(
                scope.spawn(move || -> std::result::Result<(), &'static str> {
                    loop {
                        let job = receiver
                            .lock()
                            .map_err(|_| "scan work queue poisoned")?
                            .recv();
                        let Ok(job) = job else { return Ok(()) };
                        let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            job.task.inspect(cli)
                        }))
                        .unwrap_or_else(|_| {
                            let mut report =
                                FileReport::error(job.path.clone(), "file scan worker panicked");
                            report.status = "panic";
                            report
                        });
                        if completed
                            .send(Completed {
                                ordinal: job.ordinal,
                                path: job.path,
                                report,
                            })
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                }),
            );
        }
        drop(completed);
        let result = {
            let mut pool = Pool {
                sender,
                receiver: results,
                pending: BTreeMap::new(),
                submitted: 0,
                emitted: 0,
                capacity: (jobs * 2) as u64,
                emit: &mut emit,
            };
            produce(&mut pool).and_then(|()| pool.finish())
        };
        for worker in workers {
            worker.join().map_err(|_| "scan worker thread panicked")??;
        }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::sync::{
        Barrier,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn workers_run_concurrently_with_bounded_ordered_results() {
        let cli = Cli::try_parse_from(["scan", "unused", "--output", "unused.json", "--jobs", "4"])
            .unwrap();
        let barrier = Arc::new(Barrier::new(4));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut output = Vec::new();
        run(
            &cli,
            |pool| {
                for index in 0..12 {
                    let path = PathBuf::from(index.to_string());
                    let barrier = Arc::clone(&barrier);
                    let active = Arc::clone(&active);
                    let peak = Arc::clone(&peak);
                    let result_path = path.clone();
                    pool.submit(
                        path.clone(),
                        Task::Probe(
                            path,
                            Box::new(move || {
                                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                                peak.fetch_max(count, Ordering::SeqCst);
                                barrier.wait();
                                active.fetch_sub(1, Ordering::SeqCst);
                                FileReport::new(result_path)
                            }),
                        ),
                    )?;
                    assert!(pool.submitted - pool.emitted <= 8);
                }
                Ok(())
            },
            |path, _| {
                output.push(path.to_path_buf());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        assert_eq!(
            output,
            (0..12)
                .map(|i| PathBuf::from(i.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn writer_errors_and_worker_panics_do_not_deadlock_or_disappear() {
        let cli = Cli::try_parse_from(["scan", "unused", "--output", "unused.json", "--jobs", "2"])
            .unwrap();
        let result = run(
            &cli,
            |pool| {
                for index in 0..8 {
                    let path = PathBuf::from(index.to_string());
                    pool.submit(path.clone(), Task::Ready(FileReport::new(path)))?;
                }
                Ok(())
            },
            |_, _| Err("synthetic writer failure".into()),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("synthetic writer failure")
        );
        let mut panics = 0;
        run(
            &cli,
            |pool| {
                pool.submit(
                    PathBuf::from("panic"),
                    Task::Probe(
                        PathBuf::from("panic"),
                        Box::new(|| {
                            panic!("synthetic worker failure");
                        }),
                    ),
                )
            },
            |_, report| {
                assert_eq!(report.status, "panic");
                assert_eq!(report.error.as_deref(), Some("file scan worker panicked"));
                panics += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(panics, 1);
    }
}
