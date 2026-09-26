//! Small authoritative UI projection. No manifests, tokens or remote absolute paths.
use super::{
    queue::QueueMetrics,
    speed::{SpeedSnapshot, SpeedStatus},
    task_model::{TaskDirection, TaskId, TaskRecord, TaskState},
};
use crate::identity::NodeId;
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};
#[derive(Clone, Debug)]
pub(super) struct TaskRow {
    pub id: TaskId,
    pub group: Option<TaskId>,
    pub name: String,
    pub peer: NodeId,
    pub direction: TaskDirection,
    pub state: TaskState,
    pub total: u64,
    pub confirmed: u64,
    pub rate: f64,
    pub diagnostic: Option<&'static str>,
    pub retryable: bool,
}
impl TaskRow {
    pub fn from_record(r: &TaskRecord, rate: f64) -> Self {
        let total = r.manifest_identity().total_bytes();
        Self {
            id: r.task_id().clone(),
            group: r.group_id().cloned(),
            name: r.relative_path().map(str::to_owned).unwrap_or_else(|| {
                r.local_path()
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            }),
            peer: NodeId::from_hex(r.peer_id().as_str()).expect("validated persisted peer"),
            direction: r.direction(),
            state: r.state(),
            total,
            confirmed: if r.state() == TaskState::Completed {
                total
            } else {
                r.progress_hint()
                    .map_or(0, |p| p.verified_bytes())
                    .min(total)
            },
            rate: if r.state() == TaskState::Transferring {
                rate.max(0.)
            } else {
                0.
            },
            diagnostic: r.diagnostic().map(|d| d.safe_message()),
            retryable: r.diagnostic().is_some_and(|d| d.is_retryable()),
        }
    }
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            if self.state == TaskState::Completed {
                100.
            } else {
                0.
            }
        } else {
            self.confirmed as f64 * 100. / self.total as f64
        }
    }
    pub fn can_pause(&self) -> bool {
        matches!(
            self.state,
            TaskState::Queued
                | TaskState::Connecting
                | TaskState::Negotiating
                | TaskState::Transferring
        )
    }
    pub fn can_continue(&self) -> bool {
        matches!(self.state, TaskState::Paused | TaskState::Interrupted)
            || (self.state == TaskState::Failed && self.retryable)
    }
    pub fn state_label(&self) -> &'static str {
        match self.state {
            TaskState::Scanning => "扫描中",
            TaskState::Queued => "排队中",
            TaskState::Connecting => "连接中",
            TaskState::Negotiating => "协商中",
            TaskState::Transferring => "传输中",
            TaskState::Pausing => "正在暂停",
            TaskState::Paused => "已暂停",
            TaskState::Finalizing => "正在发布确认",
            TaskState::Completed => "已完成",
            TaskState::Interrupted => "中断待继续",
            TaskState::Failed => "失败",
        }
    }
}
#[derive(Clone, Debug)]
pub(super) struct GroupRow {
    pub id: TaskId,
    pub name: String,
    pub children: usize,
    pub complete: usize,
    pub failures: usize,
    pub total: u64,
    pub confirmed: u64,
}
impl GroupRow {
    pub fn label(&self) -> String {
        let state = if self.complete == self.children {
            "全部完成"
        } else if self.failures > 0 {
            "部分中断/失败"
        } else {
            "进行中"
        };
        format!(
            "{} · {state} · {}/{} 项 · {} / {} 字节",
            self.name, self.complete, self.children, self.confirmed, self.total
        )
    }
}
#[derive(Clone, Debug)]
pub(super) enum ListRow {
    Group(GroupRow),
    Task(TaskRow),
}
pub(super) struct Snapshot {
    pub tasks: Vec<TaskRow>,
    pub queue: QueueMetrics,
    pub speeds: HashMap<NodeId, SpeedSnapshot>,
}
impl Snapshot {
    pub fn list(&self, expanded: &HashSet<TaskId>) -> Vec<ListRow> {
        let mut groups: HashMap<TaskId, GroupRow> = HashMap::new();
        for t in &self.tasks {
            if let Some(id) = &t.group {
                let g = groups.entry(id.clone()).or_insert_with(|| GroupRow {
                    id: id.clone(),
                    name: t.name.split('/').next().unwrap_or(&t.name).to_owned(),
                    children: 0,
                    complete: 0,
                    failures: 0,
                    total: 0,
                    confirmed: 0,
                });
                g.children += 1;
                g.complete += usize::from(t.state == TaskState::Completed);
                g.failures += usize::from(matches!(
                    t.state,
                    TaskState::Failed | TaskState::Interrupted
                ));
                g.total = g.total.saturating_add(t.total);
                g.confirmed = g.confirmed.saturating_add(t.confirmed);
            }
        }
        let mut seen = HashSet::new();
        let mut rows = Vec::new();
        for t in &self.tasks {
            if let Some(id) = &t.group {
                if seen.insert(id.clone()) {
                    rows.push(ListRow::Group(groups[id].clone()));
                }
                if !expanded.contains(id) {
                    continue;
                }
            }
            rows.push(ListRow::Task(t.clone()));
        }
        rows
    }
}
#[derive(Clone)]
pub(super) struct SpeedView {
    pub snapshot: SpeedSnapshot,
    pub instant: f64,
    updated: Instant,
}
#[derive(Default)]
pub(super) struct SpeedViews(pub HashMap<NodeId, SpeedView>);
impl SpeedViews {
    pub fn update(&mut self, incoming: HashMap<NodeId, SpeedSnapshot>, now: Instant) {
        for (peer, old) in &mut self.0 {
            if !incoming.contains_key(peer) && old.snapshot.status == SpeedStatus::Running {
                old.snapshot.status = SpeedStatus::Interrupted;
                old.snapshot.bytes_per_second = 0.;
                old.instant = 0.;
            }
        }
        for (peer, s) in incoming {
            let old = self.0.get(&peer);
            let same = old.is_some_and(|o| o.snapshot.test_id == s.test_id);
            let previous = old.filter(|_| same);
            let advanced = previous.is_none_or(|o| s.elapsed > o.snapshot.elapsed);
            let instant = if s.status != SpeedStatus::Running {
                0.
            } else if let Some(o) = previous {
                if advanced {
                    s.bytes.saturating_sub(o.snapshot.bytes) as f64
                        / (s.elapsed - o.snapshot.elapsed).as_secs_f64().max(0.000001)
                } else if now.duration_since(o.updated) > Duration::from_secs(2) {
                    0.
                } else {
                    o.instant
                }
            } else {
                s.bytes as f64 / s.elapsed.as_secs_f64().max(0.000001)
            };
            let updated = if advanced {
                now
            } else {
                previous.map_or(now, |o| o.updated)
            };
            self.0.insert(
                peer,
                SpeedView {
                    snapshot: s,
                    instant,
                    updated,
                },
            );
        }
        while self.0.len() > super::network_state::MAX_PEERS {
            let oldest = self
                .0
                .iter()
                .filter(|(_, v)| v.snapshot.status != SpeedStatus::Running)
                .min_by_key(|(_, v)| v.updated)
                .map(|(p, _)| *p);
            let Some(peer) = oldest else {
                break;
            };
            self.0.remove(&peer);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::super::protocol::SpeedDirection;
    use super::*;
    #[test]
    fn speed_delta_staleness_restart_cancel_and_disconnect_are_truthful() {
        let peer = crate::identity::Identity::generate().node_id();
        let now = Instant::now();
        let mut views = SpeedViews::default();
        let mut s = SpeedSnapshot {
            test_id: TaskId::generate(),
            direction: SpeedDirection::Upload,
            owner: peer,
            seconds: 30,
            status: SpeedStatus::Running,
            bytes: 100,
            elapsed: Duration::from_secs(1),
            bytes_per_second: 100.,
            rtt: Duration::ZERO,
        };
        views.update(HashMap::from([(peer, s.clone())]), now);
        s.bytes = 500;
        s.elapsed = Duration::from_secs(2);
        s.bytes_per_second = 250.;
        views.update(
            HashMap::from([(peer, s.clone())]),
            now + Duration::from_secs(1),
        );
        assert_eq!(views.0[&peer].instant, 400.);
        assert_eq!(views.0[&peer].snapshot.bytes_per_second, 250.);
        views.update(
            HashMap::from([(peer, s.clone())]),
            now + Duration::from_secs(4),
        );
        assert_eq!(views.0[&peer].instant, 0.);
        s.test_id = TaskId::generate();
        s.bytes = 0;
        s.elapsed = Duration::ZERO;
        views.update(
            HashMap::from([(peer, s.clone())]),
            now + Duration::from_secs(5),
        );
        assert_eq!(views.0[&peer].instant, 0.);
        views.update(HashMap::new(), now + Duration::from_secs(6));
        assert_eq!(views.0[&peer].snapshot.status, SpeedStatus::Interrupted);
        assert_eq!(views.0[&peer].snapshot.bytes_per_second, 0.);
        s.status = SpeedStatus::Cancelled;
        s.bytes_per_second = 0.;
        views.update(HashMap::from([(peer, s)]), now + Duration::from_secs(7));
        assert_eq!(views.0[&peer].instant, 0.);
    }
    #[test]
    fn group_partial_failure_and_empty_file_do_not_become_completed() {
        let peer = crate::identity::Identity::generate().node_id();
        let group = TaskId::generate();
        let mut a = TaskRow {
            id: TaskId::generate(),
            group: Some(group.clone()),
            name: "中文/空文件".into(),
            peer,
            direction: TaskDirection::Receive,
            state: TaskState::Paused,
            total: 0,
            confirmed: 0,
            rate: 0.,
            diagnostic: None,
            retryable: false,
        };
        assert_eq!(a.percent(), 0.);
        assert!(a.can_continue());
        assert!(!a.can_pause());
        a.state = TaskState::Completed;
        assert_eq!(a.percent(), 100.);
        let mut b = a.clone();
        b.id = TaskId::generate();
        b.state = TaskState::Interrupted;
        b.total = 10;
        b.confirmed = 4;
        let view = Snapshot {
            tasks: vec![a, b],
            queue: QueueMetrics {
                pending: 0,
                active_files: 0,
                active_metadata: 0,
                limit: 1,
                converging: false,
            },
            speeds: HashMap::new(),
        };
        let collapsed = view.list(&HashSet::new());
        assert_eq!(collapsed.len(), 1);
        let ListRow::Group(g) = &collapsed[0] else {
            panic!()
        };
        assert_eq!(g.complete, 1);
        assert_eq!(g.failures, 1);
        assert!(g.label().contains("部分"));
        assert_eq!(view.list(&HashSet::from([group])).len(), 3);
    }
    #[test]
    fn terminal_speed_history_is_bounded_without_evicting_a_running_test() {
        let now = Instant::now();
        let mut views = SpeedViews::default();
        let oldest = crate::identity::Identity::generate().node_id();
        let template = SpeedSnapshot {
            test_id: TaskId::generate(),
            direction: SpeedDirection::Upload,
            owner: oldest,
            seconds: 30,
            status: SpeedStatus::Completed,
            bytes: 100,
            elapsed: Duration::from_secs(1),
            bytes_per_second: 100.,
            rtt: Duration::ZERO,
        };
        views.update(HashMap::from([(oldest, template.clone())]), now);
        for n in 1..=super::super::network_state::MAX_PEERS {
            let peer = crate::identity::Identity::generate().node_id();
            let mut s = template.clone();
            s.test_id = TaskId::generate();
            views.update(
                HashMap::from([(peer, s)]),
                now + Duration::from_secs(n as u64),
            );
        }
        let active = crate::identity::Identity::generate().node_id();
        let mut s = template;
        s.test_id = TaskId::generate();
        s.status = SpeedStatus::Running;
        views.update(HashMap::from([(active, s)]), now + Duration::from_secs(30));
        assert_eq!(views.0.len(), super::super::network_state::MAX_PEERS);
        assert!(!views.0.contains_key(&oldest));
        assert_eq!(views.0[&active].snapshot.status, SpeedStatus::Running);
    }
}
