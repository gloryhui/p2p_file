//! Snapshot-derived outcome alerts. No paths, names, credentials or peer IDs
//! cross the OS notification boundary. Historical snapshots establish a baseline.
use super::{
    task_model::{TaskId, TaskState},
    ui_model::TaskRow,
};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    time::{Duration, Instant},
};
const COALESCE: Duration = Duration::from_secs(2);
const QUEUE: usize = 32;
const MAX_WAITERS: usize = 8;
#[cfg(target_os = "windows")]
const APP_ID: &str = "io.github.gloryhui.p2p-file";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Notice {
    pub focus: TaskId,
    pub completed: usize,
    pub failed: usize,
}
impl Notice {
    fn title(&self) -> &'static str {
        if self.failed == 0 {
            "P2P File · 传输完成"
        } else {
            "P2P File · 传输需要处理"
        }
    }
    fn body(&self) -> String {
        format!(
            "已完成 {} 项，失败或中断 {} 项。点击查看任务。",
            self.completed, self.failed
        )
    }
    fn merge(&mut self, other: Self) {
        if self.failed == 0 && other.failed > 0 {
            self.focus = other.focus;
        }
        self.completed = self.completed.saturating_add(other.completed);
        self.failed = self.failed.saturating_add(other.failed);
    }
}
#[derive(Default)]
pub(super) struct OutcomeAlerts {
    initialized: bool,
    tasks: HashMap<TaskId, TaskState>,
    groups: HashMap<TaskId, (bool, bool)>,
    pending: Option<(Instant, Notice)>,
}
fn failed(state: TaskState) -> bool {
    matches!(state, TaskState::Failed | TaskState::Interrupted)
}
impl OutcomeAlerts {
    pub fn clear_pending(&mut self) {
        self.pending = None;
    }
    pub fn observe(&mut self, rows: &[TaskRow], enabled: bool, now: Instant) -> Option<Notice> {
        let mut outcomes = Vec::new();
        let mut grouped: HashMap<TaskId, Vec<&TaskRow>> = HashMap::new();
        for row in rows {
            if let Some(group) = &row.group {
                grouped.entry(group.clone()).or_default().push(row);
            } else if self.initialized
                && self.tasks.get(&row.id) != Some(&row.state)
                && (row.state == TaskState::Completed || failed(row.state))
            {
                outcomes.push(Notice {
                    focus: row.id.clone(),
                    completed: usize::from(row.state == TaskState::Completed),
                    failed: usize::from(failed(row.state)),
                });
            }
        }
        let mut current_groups = HashMap::new();
        for (id, children) in grouped {
            let complete = children.iter().all(|r| r.state == TaskState::Completed);
            let errors = children.iter().filter(|r| failed(r.state)).count();
            let previous = self.groups.get(&id).copied().unwrap_or((false, false));
            if self.initialized && ((complete && !previous.0) || (errors > 0 && !previous.1)) {
                let focus = children
                    .iter()
                    .find(|r| failed(r.state))
                    .unwrap_or(&children[0])
                    .id
                    .clone();
                outcomes.push(Notice {
                    focus,
                    completed: if complete { children.len() } else { 0 },
                    failed: errors,
                });
            }
            current_groups.insert(id, (complete, errors > 0));
        }
        self.tasks = rows.iter().map(|r| (r.id.clone(), r.state)).collect();
        self.groups = current_groups;
        self.initialized = true;
        if !enabled {
            self.pending = None;
            return None;
        }
        for notice in outcomes {
            match &mut self.pending {
                Some((_, pending)) => pending.merge(notice),
                None => self.pending = Some((now, notice)),
            }
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|(start, _)| now.duration_since(*start) >= COALESCE)
        {
            self.pending.take().map(|(_, notice)| notice)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
pub(super) enum AlertEvent {
    Open(TaskId),
    Ready,
    Unavailable,
}
enum Request {
    Check(u64),
    Show(u64, Notice),
}
#[derive(Debug)]
struct Envelope {
    generation: u64,
    event: AlertEvent,
}
#[derive(Clone)]
pub(super) struct NativeAlerts {
    requests: SyncSender<Request>,
    events: Arc<Mutex<Receiver<Envelope>>>,
    enabled: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
    overloaded: Arc<AtomicBool>,
}
impl NativeAlerts {
    pub fn new(enabled: bool) -> Self {
        let (requests, incoming) = mpsc::sync_channel(QUEUE);
        let (events, outgoing) = mpsc::sync_channel(QUEUE);
        let active = Arc::new(AtomicBool::new(enabled));
        let generation = Arc::new(AtomicU64::new(1));
        let worker_active = active.clone();
        let worker_generation = generation.clone();
        let _ = std::thread::Builder::new().name("p2p-notifications".into()).spawn(move || {
            let waiters = Arc::new(AtomicUsize::new(0));
            let mut prepared: Option<(u64, bool)> = None;
            while let Ok(request) = incoming.recv() {
                let (epoch, notice) = match request { Request::Check(epoch) => (epoch, None), Request::Show(epoch, notice) => (epoch, Some(notice)) };
                if !worker_active.load(Ordering::Acquire) || epoch != worker_generation.load(Ordering::Acquire) { continue; }
                if prepared.as_ref().is_none_or(|(g, _)| *g != epoch) {
                    let ready = native_prepare().is_ok();
                    prepared = Some((epoch, ready));
                    let _ = events.try_send(Envelope { generation: epoch, event: if ready { AlertEvent::Ready } else { AlertEvent::Unavailable } });
                }
                if !prepared.is_some_and(|(_, ready)| ready) { continue; }
                if !worker_active.load(Ordering::Acquire) || epoch != worker_generation.load(Ordering::Acquire) { continue; }
                let Some(notice) = notice else { continue; };
                if waiters.load(Ordering::Acquire) >= MAX_WAITERS {
                    let _ = events.try_send(Envelope { generation: epoch, event: AlertEvent::Unavailable });
                    continue;
                }
                match native_show(&notice) {
                    Ok(handle) => {
                        let _ = events.try_send(Envelope { generation: epoch, event: AlertEvent::Ready });
                        waiters.fetch_add(1, Ordering::AcqRel);
                        let counter = waiters.clone();
                        let failed_counter = waiters.clone();
                        let action_events = events.clone();
                        let result = std::thread::Builder::new().name("p2p-notification-response".into()).spawn(move || {
                            struct Release(Arc<AtomicUsize>);
                            impl Drop for Release { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::AcqRel); } }
                            let _release = Release(counter);
                            handle(Box::new(move |response: &notify_rust::NotificationResponse| {
                                if matches!(response, notify_rust::NotificationResponse::Default)
                                    || matches!(response, notify_rust::NotificationResponse::Action(action) if action == "open" || action == "default") {
                                    let _ = action_events.try_send(Envelope { generation: epoch, event: AlertEvent::Open(notice.focus.clone()) });
                                }
                            }));
                        });
                        if result.is_err() {
                            failed_counter.fetch_sub(1, Ordering::AcqRel);
                            let _ = events.try_send(Envelope { generation: epoch, event: AlertEvent::Unavailable });
                        }
                    }
                    Err(_) => { let _ = events.try_send(Envelope { generation: epoch, event: AlertEvent::Unavailable }); }
                }
            }
        });
        let alerts = Self {
            requests,
            events: Arc::new(Mutex::new(outgoing)),
            enabled: active,
            generation,
            overloaded: Arc::new(AtomicBool::new(false)),
        };
        if enabled && alerts.requests.try_send(Request::Check(1)).is_err() {
            alerts.overloaded.store(true, Ordering::Release);
        }
        alerts
    }
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
        self.overloaded.store(false, Ordering::Release);
        let epoch = self
            .generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        if enabled && self.requests.try_send(Request::Check(epoch)).is_err() {
            self.overloaded.store(true, Ordering::Release);
        }
    }
    pub fn show(&self, notice: Notice) {
        if self.enabled.load(Ordering::Acquire)
            && self
                .requests
                .try_send(Request::Show(
                    self.generation.load(Ordering::Acquire),
                    notice,
                ))
                .is_err()
        {
            self.overloaded.store(true, Ordering::Release);
        }
    }

    pub fn poll(&self) -> Vec<AlertEvent> {
        let epoch = self.generation.load(Ordering::Acquire);
        let mut events: Vec<_> = self
            .events
            .lock()
            .unwrap()
            .try_iter()
            .filter(|event| event.generation == epoch && self.enabled.load(Ordering::Acquire))
            .map(|event| event.event)
            .collect();
        if self.overloaded.swap(false, Ordering::AcqRel) && self.enabled.load(Ordering::Acquire) {
            events.push(AlertEvent::Unavailable);
        }
        events
    }
}
type NativeResponse = Box<dyn FnOnce(&notify_rust::NotificationResponse) + Send>;
// The Windows backend returns a public handle from a private module without
// re-exporting its name. Keep the inferred native type inside an owned closure.
fn native_show(notice: &Notice) -> Result<impl FnOnce(NativeResponse) + Send + use<>, ()> {
    let mut notification = notify_rust::Notification::new();
    notification
        .appname("P2P File")
        .summary(notice.title())
        .body(&notice.body())
        .timeout(5000)
        .action("open", "查看任务");
    #[cfg(target_os = "linux")]
    notification.action("default", "查看任务");
    #[cfg(target_os = "windows")]
    notification.app_id(APP_ID);
    let handle = notification.show().map_err(|_| ())?;
    Ok(move |response: NativeResponse| {
        let _ = handle.wait_for_response(response);
    })
}
fn native_prepare() -> Result<(), ()> {
    #[cfg(target_os = "linux")]
    notify_rust::get_server_information().map_err(|_| ())?;
    #[cfg(target_os = "macos")]
    {
        notify_rust::check_bundle().map_err(|_| ())?;
        if !notify_rust::request_auth_blocking().map_err(|_| ())? {
            return Err(());
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::ptr;
        use windows_sys::Win32::{
            System::Registry::*, UI::Shell::SetCurrentProcessExplicitAppUserModelID,
        };
        let wide = |text: &str| text.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let app = wide(APP_ID);
        if unsafe { SetCurrentProcessExplicitAppUserModelID(app.as_ptr()) } < 0 {
            return Err(());
        }
        let path = wide(&format!(r"Software\Classes\AppUserModelId\{APP_ID}"));
        let mut key = ptr::null_mut();
        let opened = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                ptr::null(),
                0,
                KEY_SET_VALUE,
                ptr::null(),
                &mut key,
                ptr::null_mut(),
            )
        };
        if opened != 0 {
            return Err(());
        }
        let name = wide("DisplayName");
        let display = wide("P2P File");
        let result = unsafe {
            let result = RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                REG_SZ,
                display.as_ptr().cast(),
                (display.len() * 2) as u32,
            );
            RegCloseKey(key);
            result
        };
        if result != 0 {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::task_model::TaskDirection;
    use super::*;
    fn row(state: TaskState) -> TaskRow {
        TaskRow {
            id: TaskId::generate(),
            group: None,
            name: "private-name".into(),
            peer: crate::identity::Identity::generate().node_id(),
            direction: TaskDirection::Receive,
            state,
            total: 10,
            confirmed: 0,
            rate: 0.,
            diagnostic: None,
            retryable: true,
            can_delete_file: false,
        }
    }
    #[test]
    fn history_and_duplicate_snapshots_never_replay_and_retries_can_report_new_outcomes() {
        let start = Instant::now();
        let mut engine = OutcomeAlerts::default();
        let mut rows = vec![
            row(TaskState::Completed),
            row(TaskState::Interrupted),
            row(TaskState::Queued),
        ];
        assert!(engine.observe(&rows, true, start).is_none());
        assert!(engine.observe(&rows, true, start + COALESCE).is_none());
        rows[2].state = TaskState::Failed;
        assert!(engine.observe(&rows, true, start + COALESCE).is_none());
        let alert = engine.observe(&rows, true, start + COALESCE * 2).unwrap();
        assert_eq!((alert.completed, alert.failed), (0, 1));
        assert!(engine.observe(&rows, true, start + COALESCE * 3).is_none());
        rows[2].state = TaskState::Queued;
        engine.observe(&rows, true, start + COALESCE * 3);
        rows[2].state = TaskState::Completed;
        engine.observe(&rows, true, start + COALESCE * 3);
        assert_eq!(
            engine
                .observe(&rows, true, start + COALESCE * 4)
                .unwrap()
                .completed,
            1
        );
    }
    #[test]
    fn directory_success_and_batch_bursts_are_aggregated_and_disabled_results_are_not_replayed() {
        let start = Instant::now();
        let mut engine = OutcomeAlerts::default();
        let group = TaskId::generate();
        let mut rows = vec![
            row(TaskState::Queued),
            row(TaskState::Queued),
            row(TaskState::Queued),
        ];
        rows[0].group = Some(group.clone());
        rows[1].group = Some(group);
        engine.observe(&rows, true, start);
        rows[0].state = TaskState::Completed;
        assert!(engine.observe(&rows, true, start + COALESCE).is_none());
        rows[1].state = TaskState::Completed;
        rows[2].state = TaskState::Completed;
        engine.observe(&rows, true, start + COALESCE);
        let notice = engine.observe(&rows, true, start + COALESCE * 2).unwrap();
        assert_eq!((notice.completed, notice.failed), (3, 0));
        rows.push(row(TaskState::Failed));
        engine.observe(&rows, false, start + COALESCE * 3);
        assert!(engine.observe(&rows, true, start + COALESCE * 4).is_none());
        rows.push(row(TaskState::Completed));
        engine.observe(&rows, true, start + COALESCE * 4);
        engine.clear_pending();
        assert!(engine.observe(&rows, true, start + COALESCE * 5).is_none());
    }
    #[test]
    fn notice_payload_contains_only_counts_and_failed_task_gets_focus() {
        let success = row(TaskState::Completed);
        let failure = row(TaskState::Failed);
        let mut notice = Notice {
            focus: success.id,
            completed: 1,
            failed: 0,
        };
        notice.merge(Notice {
            focus: failure.id.clone(),
            completed: 0,
            failed: 1,
        });
        assert_eq!(notice.focus, failure.id);
        assert_eq!((notice.completed, notice.failed), (1, 1));
        assert!(!notice.body().contains("private-name"));
        assert!(!notice.body().contains(&failure.peer.to_hex()));
        assert!(!notice.body().contains(failure.id.as_str()));
    }
    #[test]
    fn disable_fences_queued_clicks_without_invoking_system_notification_services() {
        let (requests, _incoming) = mpsc::sync_channel(QUEUE);
        let (events, outgoing) = mpsc::sync_channel(QUEUE);
        let alerts = NativeAlerts {
            requests,
            events: Arc::new(Mutex::new(outgoing)),
            enabled: Arc::new(AtomicBool::new(true)),
            generation: Arc::new(AtomicU64::new(1)),
            overloaded: Arc::new(AtomicBool::new(false)),
        };
        events
            .try_send(Envelope {
                generation: 1,
                event: AlertEvent::Open(TaskId::generate()),
            })
            .unwrap();
        alerts.set_enabled(false);
        assert!(alerts.poll().is_empty());
        alerts.set_enabled(true);
        events
            .try_send(Envelope {
                generation: 1,
                event: AlertEvent::Ready,
            })
            .unwrap();
        assert!(alerts.poll().is_empty());
        events
            .try_send(Envelope {
                generation: 3,
                event: AlertEvent::Ready,
            })
            .unwrap();
        assert!(matches!(alerts.poll().as_slice(), [AlertEvent::Ready]));
        for _ in 0..QUEUE {
            let _ = alerts.requests.try_send(Request::Check(3));
        }
        alerts.show(Notice {
            focus: TaskId::generate(),
            completed: 1,
            failed: 0,
        });
        assert!(matches!(
            alerts.poll().as_slice(),
            [AlertEvent::Unavailable]
        ));
        assert!(alerts.poll().is_empty());
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires isolated mock org.freedesktop.Notifications service"]
    fn native_notification_dbus_fixture_delivers_counts_and_routes_click() {
        assert_eq!(
            std::env::var("P2P_NOTIFICATION_FIXTURE").as_deref(),
            Ok("1")
        );
        let alerts = NativeAlerts::new(true);
        let id = TaskId::generate();
        alerts.show(Notice {
            focus: id.clone(),
            completed: 3,
            failed: 1,
        });
        let start = Instant::now();
        let mut ready = false;
        loop {
            for event in alerts.poll() {
                match event {
                    AlertEvent::Ready => ready = true,
                    AlertEvent::Unavailable => panic!("mock native notifications unavailable"),
                    AlertEvent::Open(task) => {
                        assert_eq!(task, id);
                        assert!(ready);
                        return;
                    }
                }
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "native click not observed"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
