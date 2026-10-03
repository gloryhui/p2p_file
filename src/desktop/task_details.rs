//! Read-only task details and bounded current-process activity measurements.
use super::task_model::{TaskDirection, TaskId, TaskRecord, TaskState};
use crate::{error::Result, identity::NodeId};
use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Selection {
    Task(TaskId),
    Group(TaskId),
}
const MAX_SAMPLES: usize = 4096;
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Sample {
    pub attempts: u32,
    pub automatic: u32,
    pub elapsed: Duration,
}
struct Measurement {
    sample: Sample,
    since: Option<Instant>,
    automatic: bool,
    serial: u64,
}
#[derive(Default)]
pub(super) struct Measurements {
    entries: HashMap<TaskId, Measurement>,
    serial: u64,
}
impl Measurements {
    pub fn start(&mut self, id: TaskId, now: Instant) {
        if !self.entries.contains_key(&id) && self.entries.len() >= MAX_SAMPLES {
            let oldest = self
                .entries
                .iter()
                .filter(|(_, measurement)| measurement.since.is_none())
                .min_by_key(|(_, measurement)| measurement.serial)
                .map(|(id, _)| id.clone());
            if let Some(oldest) = oldest {
                self.entries.remove(&oldest);
            } else {
                return;
            }
        }
        self.serial = self.serial.wrapping_add(1);
        let measurement = self.entries.entry(id).or_insert(Measurement {
            sample: Sample::default(),
            since: None,
            automatic: false,
            serial: self.serial,
        });
        if measurement.since.is_none() {
            measurement.sample.attempts = measurement.sample.attempts.saturating_add(1);
            measurement.since = Some(now);
            measurement.automatic = false;
            measurement.serial = self.serial;
        }
    }
    pub fn automatic(&mut self, id: &TaskId) {
        if let Some(measurement) = self.entries.get_mut(id)
            && measurement.since.is_some()
            && !measurement.automatic
        {
            measurement.sample.automatic = measurement.sample.automatic.saturating_add(1);
            measurement.automatic = true;
        }
    }
    pub fn finish(&mut self, id: &TaskId, now: Instant) {
        self.serial = self.serial.wrapping_add(1);
        if let Some(measurement) = self.entries.get_mut(id)
            && let Some(since) = measurement.since.take()
        {
            measurement.serial = self.serial;
            measurement.sample.elapsed = measurement
                .sample
                .elapsed
                .saturating_add(now.saturating_duration_since(since));
        }
    }
    pub fn sample(&self, id: &TaskId, now: Instant) -> Option<Sample> {
        self.entries.get(id).map(|measurement| {
            let mut sample = measurement.sample;
            if let Some(since) = measurement.since {
                sample.elapsed = sample
                    .elapsed
                    .saturating_add(now.saturating_duration_since(since));
            }
            sample
        })
    }
    pub fn retain(&mut self, records: &[TaskRecord]) {
        let ids: std::collections::HashSet<_> = records.iter().map(TaskRecord::task_id).collect();
        self.entries
            .retain(|id, measurement| measurement.since.is_some() || ids.contains(id));
    }
}
#[derive(Clone, Debug)]
pub(super) struct Member {
    pub id: TaskId,
    pub name: String,
    pub directory: bool,
    pub state: &'static str,
    pub total: u64,
    pub confirmed: u64,
    pub diagnostic: Option<&'static str>,
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Counts {
    pub files: usize,
    pub directories: usize,
    pub completed: usize,
    pub failed: usize,
    pub paused: usize,
    pub interrupted: usize,
    pub waiting: usize,
    pub queued: usize,
    pub active: usize,
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct RunTotals {
    pub covered: usize,
    pub attempts: u64,
    pub retries: u64,
    pub automatic: u64,
    pub seconds: u64,
}
#[derive(Clone, Debug)]
pub(super) struct Detail {
    pub scope_label: &'static str,
    pub parent_group: Option<TaskId>,
    pub selection: Selection,
    pub name: String,
    pub peer: NodeId,
    pub direction: TaskDirection,
    pub state: &'static str,
    pub total: u64,
    pub confirmed: u64,
    pub rate: f64,
    pub eta: Option<u64>,
    pub wall_seconds: Option<u64>,
    pub run: RunTotals,
    pub counts: Counts,
    pub members: Vec<Member>,
    pub local_path: PathBuf,
    pub reveal_label: &'static str,
    pub errors: Vec<(&'static str, usize, bool)>,
}
fn records_for<'a>(records: &'a [TaskRecord], selected: &Selection) -> Vec<&'a TaskRecord> {
    match selected {
        Selection::Task(id) => records
            .iter()
            .filter(|record| record.task_id() == id)
            .collect(),
        Selection::Group(id) => records
            .iter()
            .filter(|record| record.group_id() == Some(id))
            .collect(),
    }
}
pub(super) fn eta(remaining: u64, rate: f64, blocked: bool) -> Option<u64> {
    if blocked || remaining == 0 || !rate.is_finite() || rate <= 0. {
        return None;
    }
    let seconds = (remaining as f64 / rate).ceil();
    // Casting would otherwise silently saturate an unsupported estimate.
    (seconds.is_finite() && seconds < u64::MAX as f64).then_some(seconds as u64)
}
fn anchor<'a>(records: &[&'a TaskRecord]) -> &'a TaskRecord {
    records
        .iter()
        .copied()
        .min_by_key(|record| {
            (
                record.directory_details().is_none(),
                record
                    .relative_path()
                    .map_or(usize::MAX, |path| path.split('/').count()),
                record.task_id().clone(),
            )
        })
        .unwrap()
}
fn location(records: &[&TaskRecord], selection: &Selection) -> Result<(PathBuf, &'static str)> {
    let record = anchor(records);
    if matches!(selection, Selection::Group(_)) && record.direction() == TaskDirection::Receive {
        return Ok((record.local_path().to_path_buf(), "定位原接收目录"));
    }
    if matches!(selection, Selection::Group(_))
        && record.file_details().is_some()
        && record.direction() == TaskDirection::Send
    {
        let root = record
            .file_details()
            .unwrap()
            .source_root
            .as_ref()
            .ok_or_else(|| super::transfer_files::failure("目录源绑定不可用"))?;
        return Ok((root.clone(), "定位源目录"));
    }
    if record.direction() == TaskDirection::Send {
        Ok((
            record.local_path().to_path_buf(),
            if record.directory_details().is_none() {
                "定位源文件"
            } else {
                "定位源目录"
            },
        ))
    } else if records
        .iter()
        .all(|record| record.state() == TaskState::Completed && record.receipt_committed())
    {
        let relative = record
            .relative_path()
            .ok_or_else(|| super::transfer_files::failure("任务缺少相对路径"))?;
        super::protocol::validate_relative_path(relative)?;
        Ok((
            record.local_path().join(relative),
            if record.file_details().is_some() {
                "定位接收文件"
            } else {
                "定位接收目录"
            },
        ))
    } else {
        Ok((record.local_path().to_path_buf(), "定位原接收目录"))
    }
}
pub(super) fn project(
    records: &[TaskRecord],
    selection: &Selection,
    rate: impl Fn(&TaskRecord) -> f64,
    sample: impl Fn(&TaskId) -> Option<Sample>,
    waiting: impl Fn(&TaskId) -> bool,
    now_ms: i64,
) -> Option<Detail> {
    let selected = records_for(records, selection);
    let first = *selected.first()?;
    if selected.iter().any(|record| {
        record.peer_id() != first.peer_id()
            || record.direction() != first.direction()
            || (first.direction() == TaskDirection::Receive
                && record.local_path() != first.local_path())
    }) {
        return None;
    }
    let mut activity_time = Duration::ZERO;
    let mut counts = Counts::default();
    let mut run = RunTotals::default();
    let mut total = 0u64;
    let mut confirmed = 0u64;
    let mut speed = 0.;
    let mut blocked = false;
    let mut members = Vec::new();
    let mut errors: HashMap<_, (usize, bool)> = HashMap::new();
    let mut started = i64::MAX;
    let mut ended = 0;
    for record in &selected {
        let is_directory = record.directory_details().is_some();
        if is_directory {
            counts.directories += 1;
        } else {
            counts.files += 1;
        }
        let pending = waiting(record.task_id());
        let state = record.state();
        if pending {
            counts.waiting += 1;
        } else {
            match state {
                TaskState::Completed => counts.completed += 1,
                TaskState::Failed => counts.failed += 1,
                TaskState::Paused => counts.paused += 1,
                TaskState::Interrupted => counts.interrupted += 1,
                TaskState::Scanning | TaskState::Queued => counts.queued += 1,
                _ => counts.active += 1,
            }
        }
        blocked |= pending
            || matches!(
                state,
                TaskState::Failed | TaskState::Paused | TaskState::Pausing | TaskState::Interrupted
            );
        let size = if is_directory {
            0
        } else {
            record.manifest_identity().total_bytes()
        };
        let bytes = if state == TaskState::Completed {
            size
        } else {
            record
                .progress_hint()
                .map_or(0, |hint| hint.verified_bytes())
                .min(size)
        };
        total = total.saturating_add(size);
        confirmed = confirmed.saturating_add(bytes);
        if state == TaskState::Transferring && !pending && !is_directory {
            let value = rate(record);
            if value.is_finite() && value > 0. {
                speed += value;
            }
        }
        if let Some(measurement) = sample(record.task_id()) {
            run.covered += 1;
            run.attempts = run.attempts.saturating_add(u64::from(measurement.attempts));
            run.retries = run
                .retries
                .saturating_add(u64::from(measurement.attempts.saturating_sub(1)));
            run.automatic = run
                .automatic
                .saturating_add(u64::from(measurement.automatic));
            activity_time = activity_time.saturating_add(measurement.elapsed);
        }
        if let Some(diagnostic) = record.diagnostic() {
            let entry = errors.entry(diagnostic.safe_message()).or_default();
            entry.0 += 1;
            entry.1 |= diagnostic.is_retryable();
        }
        started = started.min(record.created_at_unix_ms());
        ended = ended.max(record.updated_at_unix_ms());
        members.push(Member {
            id: record.task_id().clone(),
            name: record
                .relative_path()
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    record
                        .local_path()
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned()
                }),
            directory: is_directory,
            state: if pending {
                "等待连接和重新授权"
            } else {
                super::ui_model::state_label(state)
            },
            total: size,
            confirmed: bytes,
            diagnostic: record
                .diagnostic()
                .map(|diagnostic| diagnostic.safe_message()),
        });
    }
    run.seconds = activity_time.as_secs();
    if !speed.is_finite() {
        speed = 0.;
    }
    let state = if selected.len() == 1 && matches!(selection, Selection::Task(_)) {
        members[0].state
    } else if counts.completed == selected.len() {
        if first.direction() == TaskDirection::Receive {
            "已接纳子项均完成"
        } else {
            "已完成"
        }
    } else if counts.failed > 0 {
        "含失败任务"
    } else if counts.paused > 0 {
        "含暂停任务"
    } else if counts.waiting > 0 {
        "等待连接和重新授权"
    } else if counts.interrupted > 0 {
        "含中断任务"
    } else if counts.active > 0 {
        "传输中"
    } else {
        "排队"
    };
    let end = if selected.iter().all(|record| record.state().is_terminal()) {
        ended
    } else {
        now_ms
    };
    let wall_seconds = end
        .checked_sub(started)
        .filter(|elapsed| *elapsed >= 0)
        .map(|elapsed| elapsed as u64 / 1000);
    let root = anchor(&selected);
    let name = if matches!(selection, Selection::Group(_)) {
        root.relative_path()
            .and_then(|relative| relative.split('/').next())
            .unwrap_or("目录组")
            .to_owned()
    } else {
        members[0].name.clone()
    };
    let (local_path, reveal_label) = location(&selected, selection).ok()?;
    let mut errors: Vec<_> = errors
        .into_iter()
        .map(|(message, (count, retryable))| (message, count, retryable))
        .collect();
    errors.sort_by_key(|entry| entry.0);
    members.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
    Some(Detail {
        parent_group: if matches!(selection, Selection::Task(_)) {
            first.group_id().cloned()
        } else {
            None
        },
        scope_label: if matches!(selection, Selection::Group(_)) {
            if first.direction() == TaskDirection::Receive {
                "当前保留的全部已接纳子项；后续到达项会更新，与主列表筛选无关"
            } else {
                "完整本机目录清单，与主列表筛选无关"
            }
        } else {
            "单个任务"
        },
        selection: selection.clone(),
        name,
        peer: NodeId::from_hex(first.peer_id().as_str()).ok()?,
        direction: first.direction(),
        state,
        total,
        confirmed,
        rate: speed,
        eta: eta(total.saturating_sub(confirmed), speed, blocked),
        wall_seconds,
        run,
        counts,
        members,
        local_path,
        reveal_label,
        errors,
    })
}
/// Revalidate the stored task's own no-follow location off the UI thread.
pub(super) fn reveal(records: &[TaskRecord], selection: &Selection) -> Result<PathBuf> {
    let selected = records_for(records, selection);
    let first = selected
        .first()
        .ok_or_else(|| super::transfer_files::failure("任务或目录组记录已不存在"))?;
    if selected.iter().any(|record| {
        record.peer_id() != first.peer_id()
            || record.direction() != first.direction()
            || (first.direction() == TaskDirection::Receive
                && record.local_path() != first.local_path())
    }) {
        return Err(super::transfer_files::failure("任务组绑定不一致"));
    }
    let record = anchor(&selected);
    let (path, _) = location(&selected, selection)?;
    if record.direction() == TaskDirection::Send {
        if matches!(selection, Selection::Group(_)) && record.file_details().is_some() {
            let _ = super::secure_fs::root(&path)?;
        } else if record.directory_details().is_none() {
            let (parent, name) = if record
                .file_details()
                .is_some_and(|details| details.source_root.is_some())
            {
                super::transfer_files::source_parent(record)?
            } else {
                let path = record
                    .local_path()
                    .parent()
                    .ok_or_else(|| super::transfer_files::failure("源目录不可用"))?;
                let parent = if path.parent().is_some() {
                    super::secure_fs::root(path)?
                } else {
                    cap_std::fs::Dir::open_ambient_dir(path, cap_std::ambient_authority())?
                };
                let name = record
                    .local_path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| super::transfer_files::failure("源文件名不可用"))?;
                (parent, name.to_owned())
            };
            let _ = super::secure_fs::open(&parent, &name, false, false)?;
        } else {
            let group_root = record.group_id().and_then(|id| {
                records
                    .iter()
                    .filter(|candidate| {
                        candidate.group_id() == Some(id)
                            && candidate.direction() == TaskDirection::Send
                            && candidate.peer_id() == record.peer_id()
                            && candidate.directory_details().is_some()
                    })
                    .min_by_key(|candidate| candidate.relative_path().unwrap().split('/').count())
            });
            let root_record = group_root.unwrap_or(record);
            let root = super::secure_fs::root(root_record.local_path())?;
            if root_record.task_id() != record.task_id() {
                let relative = record
                    .relative_path()
                    .unwrap()
                    .split_once('/')
                    .map(|(_, path)| path)
                    .ok_or_else(|| super::transfer_files::failure("源目录绑定无效"))?;
                if root_record.local_path().join(relative) != record.local_path() {
                    return Err(super::transfer_files::failure("源目录绑定无效"));
                }
                let (parent, name) = super::secure_fs::parent(&root, relative, false)?;
                let _ = super::secure_fs::child(&parent, &name, false)?;
            }
        }
    } else {
        let root = super::secure_fs::root(record.local_path())?;
        if path != record.local_path() {
            let (parent, name) =
                super::secure_fs::parent(&root, record.relative_path().unwrap(), false)?;
            if record.file_details().is_some() {
                let _ = super::secure_fs::open(&parent, &name, false, false)?;
            } else {
                let _ = super::secure_fs::child(&parent, &name, false)?;
            }
        }
    }
    Ok(path)
}
pub(super) fn duration(seconds: u64) -> String {
    if seconds >= 86_400 {
        format!("{} 天 {} 小时", seconds / 86_400, (seconds % 86_400) / 3600)
    } else {
        format!(
            "{}:{:02}:{:02}",
            seconds / 3600,
            seconds % 3600 / 60,
            seconds % 60
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::task_model::{PeerId, ProgressHint, TaskDiagnostic, TaskErrorCode};
    use super::*;
    use crate::{
        identity::Identity,
        protocol::manifest::{ChunkHash, FileManifest, MIN_CHUNK_SIZE},
    };
    fn file(
        peer: NodeId,
        root: &std::path::Path,
        name: &str,
        group: Option<TaskId>,
        state: TaskState,
        direction: TaskDirection,
    ) -> TaskRecord {
        let data = vec![17; 64];
        let manifest = FileManifest::new(
            name,
            data.len() as u64,
            MIN_CHUNK_SIZE,
            vec![ChunkHash::of(&data)],
        )
        .unwrap();
        let relative = if group.is_some() {
            format!("{}/{name}", root.file_name().unwrap().to_str().unwrap())
        } else {
            name.to_owned()
        };
        let mut record = TaskRecord::new_file(
            TaskId::generate(),
            PeerId::from_node_id(peer),
            direction,
            if direction == TaskDirection::Send {
                root.join(name)
            } else {
                root.to_path_buf()
            },
            relative,
            manifest,
        )
        .unwrap();
        record
            .set_selection_binding(
                group.clone(),
                if group.is_some() && direction == TaskDirection::Send {
                    Some(root.to_path_buf())
                } else {
                    None
                },
            )
            .unwrap();
        let now = record.created_at_unix_ms();
        for next in [
            TaskState::Queued,
            TaskState::Connecting,
            TaskState::Negotiating,
            TaskState::Transferring,
        ] {
            if state == TaskState::Scanning {
                break;
            }
            record.transition_to(next, None, now + 1000).unwrap();
            if next == state {
                break;
            }
        }
        match state {
            TaskState::Paused => {
                record
                    .transition_to(TaskState::Pausing, None, now + 2000)
                    .unwrap();
                record
                    .transition_to(TaskState::Paused, None, now + 3000)
                    .unwrap();
            }
            TaskState::Failed => record
                .transition_to(
                    state,
                    Some(TaskDiagnostic::new(TaskErrorCode::SourceUnavailable, true)),
                    now + 3000,
                )
                .unwrap(),
            TaskState::Interrupted => record
                .transition_to(
                    state,
                    Some(TaskDiagnostic::new(
                        TaskErrorCode::NetworkInterrupted,
                        false,
                    )),
                    now + 3000,
                )
                .unwrap(),
            TaskState::Completed => {
                record
                    .transition_to(TaskState::Finalizing, None, now + 2000)
                    .unwrap();
                if direction == TaskDirection::Receive {
                    record.prepare_publication().unwrap();
                }
                record.commit_receipt(now + 3000).unwrap();
            }
            TaskState::Finalizing => record.transition_to(state, None, now + 3000).unwrap(),
            _ => {}
        }
        record
            .set_progress_hint(ProgressHint::new(32, now + 3000))
            .unwrap();
        record
    }
    #[test]
    fn measurements_exclude_pauses_count_real_attempts_and_mark_auto_once() {
        let mut measures = Measurements::default();
        let id = TaskId::generate();
        let now = Instant::now();
        assert!(measures.sample(&id, now).is_none());
        measures.start(id.clone(), now);
        measures.start(id.clone(), now + Duration::from_secs(1));
        measures.finish(&id, now + Duration::from_secs(2));
        measures.finish(&id, now + Duration::from_secs(5));
        assert_eq!(
            measures
                .sample(&id, now + Duration::from_secs(50))
                .unwrap()
                .elapsed,
            Duration::from_secs(2)
        );
        measures.start(id.clone(), now + Duration::from_secs(50));
        measures.automatic(&id);
        measures.automatic(&id);
        let sample = measures.sample(&id, now + Duration::from_secs(53)).unwrap();
        assert_eq!(sample.attempts, 2);
        assert_eq!(sample.automatic, 1);
        assert_eq!(sample.elapsed, Duration::from_secs(5));
        measures.finish(&id, now + Duration::from_secs(55));
        measures.retain(&[]);
        assert!(measures.sample(&id, now).is_none());
        assert!(Measurements::default().sample(&id, now).is_none()); // Restart has no fabricated history.
    }
    #[test]
    fn measurements_are_bounded_and_do_not_retire_live_io() {
        let mut measures = Measurements::default();
        let now = Instant::now();
        let active = TaskId::generate();
        measures.start(active.clone(), now);
        for _ in 0..MAX_SAMPLES + 10 {
            let id = TaskId::generate();
            measures.start(id.clone(), now);
            measures.finish(&id, now);
        }
        assert_eq!(measures.entries.len(), MAX_SAMPLES);
        assert!(measures.sample(&active, now).is_some());
        measures.retain(&[]);
        assert_eq!(measures.entries.len(), 1);
    }
    #[test]
    fn eta_rejects_no_evidence_and_stopped_states_never_reuse_rates() {
        assert_eq!(eta(101, 10., false), Some(11));
        for rate in [0., -1., f64::NAN, f64::INFINITY, f64::MIN_POSITIVE] {
            assert_eq!(eta(u64::MAX, rate, false), None);
        }
        assert_eq!(eta(100, 10., true), None);
        assert_eq!(eta(0, 10., false), None);
        let root = std::env::temp_dir().join("detail-source");
        let peer = Identity::generate().node_id();
        for state in [
            TaskState::Scanning,
            TaskState::Queued,
            TaskState::Paused,
            TaskState::Interrupted,
            TaskState::Failed,
            TaskState::Completed,
            TaskState::Finalizing,
        ] {
            let record = file(peer, &root, "file.bin", None, state, TaskDirection::Send);
            let detail = project(
                std::slice::from_ref(&record),
                &Selection::Task(record.task_id().clone()),
                |_| 100.,
                |_| None,
                |_| false,
                record.created_at_unix_ms() + 10_000,
            )
            .unwrap();
            assert_eq!(detail.rate, 0.);
            assert_eq!(detail.eta, None);
            assert_eq!(detail.run.covered, 0);
        }
        let record = file(
            peer,
            &root,
            "active.bin",
            None,
            TaskState::Transferring,
            TaskDirection::Send,
        );
        let active = project(
            std::slice::from_ref(&record),
            &Selection::Task(record.task_id().clone()),
            |_| 16.,
            |_| None,
            |_| false,
            record.created_at_unix_ms() + 10_000,
        )
        .unwrap();
        assert_eq!(active.eta, Some(2));
        assert_eq!(active.wall_seconds, Some(10));
        let waiting = project(
            std::slice::from_ref(&record),
            &Selection::Task(record.task_id().clone()),
            |_| 16.,
            |_| None,
            |_| true,
            record.created_at_unix_ms() - 1,
        )
        .unwrap();
        assert_eq!(waiting.rate, 0.);
        assert_eq!(waiting.eta, None);
        assert_eq!(waiting.wall_seconds, None);
    }
    #[test]
    fn complete_group_projection_includes_blocked_children_and_subsecond_activity() {
        let root = std::env::temp_dir().join("detail-group");
        let peer = Identity::generate().node_id();
        let group = TaskId::generate();
        let records: Vec<_> = [
            TaskState::Completed,
            TaskState::Transferring,
            TaskState::Paused,
            TaskState::Failed,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, state)| {
            file(
                peer,
                &root,
                &format!("{index}.bin"),
                Some(group.clone()),
                state,
                TaskDirection::Send,
            )
        })
        .collect();
        let detail = project(
            &records,
            &Selection::Group(group),
            |_| 16.,
            |_| {
                Some(Sample {
                    attempts: 2,
                    automatic: 1,
                    elapsed: Duration::from_millis(400),
                })
            },
            |_| false,
            records[0].created_at_unix_ms() + 10_000,
        )
        .unwrap();
        assert_eq!(detail.members.len(), 4);
        assert_eq!(detail.counts.completed, 1);
        assert_eq!(detail.counts.paused, 1);
        assert_eq!(detail.counts.failed, 1);
        assert_eq!(detail.total, 256);
        assert_eq!(detail.confirmed, 160);
        assert_eq!(detail.rate, 16.);
        assert_eq!(detail.eta, None);
        assert_eq!(detail.run.attempts, 8);
        assert_eq!(detail.run.retries, 4);
        assert_eq!(detail.run.automatic, 4);
        assert_eq!(detail.run.seconds, 1);
        assert_eq!(detail.errors, vec![("本机源文件不可用", 1, true)]);
        // A receiver cannot infer that a remote directory inventory is finished.
        let receive = file(
            peer,
            &root,
            "received.bin",
            Some(TaskId::generate()),
            TaskState::Completed,
            TaskDirection::Receive,
        );
        let projected = project(
            std::slice::from_ref(&receive),
            &Selection::Group(receive.group_id().unwrap().clone()),
            |_| 1.,
            |_| None,
            |_| false,
            i64::MAX,
        )
        .unwrap();
        assert_eq!(projected.state, "已接纳子项均完成");
        assert_eq!(projected.local_path, root);
        assert_eq!(projected.wall_seconds, Some(3));
    }
    #[test]
    fn task_and_group_ids_are_distinct_selections_and_missing_records_close_projection() {
        let root = std::env::temp_dir().join("detail-collision");
        let peer = Identity::generate().node_id();
        let one = file(
            peer,
            &root,
            "single.bin",
            None,
            TaskState::Transferring,
            TaskDirection::Send,
        );
        let group = one.task_id().clone();
        let two = file(
            peer,
            &root,
            "group.bin",
            Some(group.clone()),
            TaskState::Queued,
            TaskDirection::Send,
        );
        let records = vec![one, two];
        let task = project(
            &records,
            &Selection::Task(group.clone()),
            |_| 1.,
            |_| None,
            |_| false,
            i64::MAX,
        )
        .unwrap();
        let folder = project(
            &records,
            &Selection::Group(group.clone()),
            |_| 1.,
            |_| None,
            |_| false,
            i64::MAX,
        )
        .unwrap();
        assert_ne!(task.members[0].id, folder.members[0].id);
        assert!(
            project(
                &[],
                &Selection::Task(group.clone()),
                |_| 1.,
                |_| None,
                |_| false,
                0
            )
            .is_none()
        );
        assert!(reveal(&[], &Selection::Group(group)).is_err());
    }
}
