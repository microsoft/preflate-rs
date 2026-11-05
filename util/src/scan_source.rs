//! Read-only selection of scan inputs from corpus or crawl SQLite catalogs.
//!
//! A completed scan run selects its recorded files; a crawl catalog selects its
//! distinct saved payloads. Both are read through a SQLite snapshot, so the input
//! set does not change while workers inspect the files.
//!
//! Recorded paths are resolved under the source root and checked for escapes,
//! symlinks, and cloud-only placeholders before reading. Database selection
//! schedules only those files rather than discovering new inputs through a
//! recursive walk, and the source catalog is separate from any output database.

use std::{
    fs,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::Value;

use crate::{
    Cli, FileReport, Result, scan_fs,
    scan_parallel::{self, Task},
};

pub struct DatabaseSource {
    pub(crate) connection: Connection,
    pub root: PathBuf,
    pub path: PathBuf,
    pub file_count: u64,
    pub(crate) run: Option<i64>,
}

impl DatabaseSource {
    pub fn open(cli: &Cli) -> Result<Self> {
        let path = fs::canonicalize(&cli.input)?;
        if let Some(output) = &cli.database
            && output.exists()
            && fs::canonicalize(output)? == path
        {
            return Err(
                "source and output databases must differ; merge the completed run afterwards"
                    .into(),
            );
        }
        let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_secs(60))?;
        connection.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
        let versions = connection
            .prepare("SELECT version FROM schema_info")?
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if versions != [1] {
            return Err("unsupported corpus database schema".into());
        }
        let (root, run) = if cli.from_run.is_some() || cli.baseline_run.is_some() {
            let (query, selection) = if let Some(id) = cli.baseline_run {
                (
                    "SELECT id,state,configuration_json,imported_files,summary_json FROM runs WHERE id=?",
                    rusqlite::types::Value::Integer(id),
                )
            } else {
                (
                    "SELECT id,state,configuration_json,imported_files,summary_json FROM runs WHERE label=?",
                    rusqlite::types::Value::Text(cli.from_run.clone().ok_or("missing source run")?),
                )
            };
            let (id, state, config, imported, summary): (i64, String, String, i64, Option<String>) =
                connection
                    .query_row(query, [selection], |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    })
                    .optional()?
                    .ok_or("unknown source run")?;
            if state != "complete" {
                return Err("source run must be complete".into());
            }
            let count: i64 = connection.query_row(
                "SELECT count(*) FROM run_files WHERE run_id=?",
                [id],
                |row| row.get(0),
            )?;
            let summary: Value =
                serde_json::from_str(summary.as_deref().ok_or("missing source summary")?)?;
            if imported != count || summary["entries"].as_i64() != Some(count) {
                return Err("source run file count does not reconcile".into());
            }
            let config: Value = serde_json::from_str(&config)?;
            let root = PathBuf::from(
                config["input"]
                    .as_str()
                    .ok_or("source run has no local input root")?,
            );
            if !root.is_absolute() || root.components().any(|part| part == Component::ParentDir) {
                return Err("source run requires an absolute local input root".into());
            }
            (root, Some(id))
        } else {
            (
                cli.source_root
                    .clone()
                    .unwrap_or_else(|| path.parent().expect("database parent").to_path_buf()),
                None,
            )
        };
        let mut source = Self {
            connection,
            root: fs::canonicalize(root)?,
            path,
            run,
            file_count: 0,
        };
        let count: i64 = match source.run {
            Some(run) => source.connection.query_row(
                "SELECT count(DISTINCT f.path) FROM run_files rf \
                 JOIN file_versions v ON v.id=rf.file_version_id \
                 JOIN files f ON f.id=v.file_id WHERE rf.run_id=?",
                [run],
                |row| row.get(0),
            )?,
            None => source.connection.query_row(
                "SELECT count(DISTINCT path) FROM saved_streams",
                [],
                |row| row.get(0),
            )?,
        };
        if count == 0 {
            return Err("database selection contains no source files".into());
        }
        source.file_count = u64::try_from(count)?;
        Ok(source)
    }

    pub fn scan(
        &self,
        output: &Path,
        cli: &Cli,
        mut emit: impl FnMut(FileReport) -> Result<()>,
    ) -> Result<()> {
        self.scan_with_paths(output, cli, |_, report| emit(report))
    }

    pub fn scan_with_paths(
        &self,
        output: &Path,
        cli: &Cli,
        emit: impl FnMut(&Path, FileReport) -> Result<()>,
    ) -> Result<()> {
        scan_parallel::run(cli, |pool| self.enqueue(output, cli, pool), emit)
    }

    fn enqueue(&self, output: &Path, cli: &Cli, pool: &mut scan_parallel::Pool<'_>) -> Result<()> {
        let query = if self.run.is_some() {
            "SELECT DISTINCT f.path FROM run_files rf JOIN file_versions v ON v.id=rf.file_version_id \
             JOIN files f ON f.id=v.file_id WHERE rf.run_id=? ORDER BY f.path"
        } else {
            "SELECT DISTINCT path FROM saved_streams ORDER BY path"
        };
        let mut statement = self.connection.prepare(query)?;
        let mut rows = if let Some(run) = self.run {
            statement.query([run])?
        } else {
            statement.query([])?
        };
        while let Some(row) = rows.next()? {
            let recorded = PathBuf::from(row.get::<_, String>(0)?);
            let path = recorded.clone();
            if path.components().any(|part| part == Component::ParentDir)
                || path.to_string_lossy().contains("://")
            {
                return Err("database contains a non-local or parent-traversing path; use --from-crawl for saved extracts".into());
            }
            let path = if path.is_absolute() {
                path
            } else {
                self.root.join(path)
            };
            let task = self.prepare(path, output, cli);
            pool.submit(recorded, task)?;
        }
        Ok(())
    }

    fn prepare(&self, path: PathBuf, output: &Path, cli: &Cli) -> Task {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => return Task::Ready(FileReport::error(path, error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            let mut report = FileReport::new(path);
            report.status = "skipped";
            report.error = Some("database input is not a regular non-symlink file".into());
            return Task::Ready(report);
        }
        for parent in path.ancestors().skip(1) {
            match fs::symlink_metadata(parent) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    let mut report = FileReport::new(path.clone());
                    report.status = "skipped";
                    report.error = Some("database input has a symlink ancestor".into());
                    return Task::Ready(report);
                }
                Err(error) => return Task::Ready(FileReport::error(path.clone(), error)),
                _ => {}
            }
        }
        if !cli.hydrate && scan_fs::cloud_only(&metadata) {
            return Task::File(path, metadata);
        }
        let canonical = match fs::canonicalize(&path) {
            Ok(path) => path,
            Err(error) => return Task::Ready(FileReport::error(path, error)),
        };
        if !canonical.starts_with(&self.root) {
            return Task::Ready(FileReport::error(
                path,
                "database input is outside the source root",
            ));
        }
        if canonical == self.path || crate::is_scan_output(&canonical, output, cli) {
            let mut report = FileReport::new(canonical);
            report.status = "skipped";
            report.error = Some("database input refers to a scanner database or output".into());
            return Task::Ready(report);
        }
        Task::File(canonical, metadata)
    }
}
