//! Bounded, in-process task events for desktop presentation.
//!
//! Events intentionally contain only task IDs, lifecycle states, and fixed
//! event kinds. They never copy local paths, remote paths, raw errors, or
//! transfer contents into a log.

use std::collections::VecDeque;

use super::task_model::{TaskId, TaskState};

const MAX_PENDING_EVENTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskEventKind {
    Created,
    StateChanged { from: TaskState, to: TaskState },
    RecoveredAfterRestart,
    ProgressHintChanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TaskEvent {
    task_id: TaskId,
    at_unix_ms: i64,
    kind: TaskEventKind,
}

impl TaskEvent {
    pub(crate) fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    pub(crate) fn at_unix_ms(&self) -> i64 {
        self.at_unix_ms
    }

    pub(crate) fn kind(&self) -> TaskEventKind {
        self.kind
    }
}

#[derive(Debug, Default)]
pub(crate) struct TaskEventBuffer {
    events: VecDeque<TaskEvent>,
    resync_required: bool,
}

impl TaskEventBuffer {
    pub(crate) fn push(&mut self, event: TaskEvent) {
        if event.kind == TaskEventKind::ProgressHintChanged {
            if let Some(existing) = self.events.iter_mut().find(|old| {
                old.task_id == event.task_id && old.kind == TaskEventKind::ProgressHintChanged
            }) {
                *existing = event;
                return;
            }
            if self.events.len() == MAX_PENDING_EVENTS {
                return;
            }
        }
        if self.events.len() == MAX_PENDING_EVENTS {
            if let Some(index) = self
                .events
                .iter()
                .position(|old| old.kind == TaskEventKind::ProgressHintChanged)
            {
                self.events.remove(index);
            } else {
                // An arbitrary number of terminal transitions cannot fit in a
                // bounded FIFO. Explicitly require authoritative resynchronization.
                self.events.pop_front();
                self.resync_required = true;
            }
        }
        self.events.push_back(event);
    }
    pub(crate) fn take_resync_required(&mut self) -> bool {
        std::mem::take(&mut self.resync_required)
    }

    pub(crate) fn drain(&mut self) -> Vec<TaskEvent> {
        self.events.drain(..).collect()
    }

    pub(crate) fn record(&mut self, task_id: TaskId, at_unix_ms: i64, kind: TaskEventKind) {
        self.push(TaskEvent {
            task_id,
            at_unix_ms,
            kind,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_buffer_is_bounded_and_contains_only_safe_domain_fields() {
        let mut buffer = TaskEventBuffer::default();
        let oldest = TaskId::generate();
        buffer.record(oldest.clone(), 1, TaskEventKind::Created);
        for at_unix_ms in 2..=MAX_PENDING_EVENTS as i64 + 1 {
            buffer.record(
                TaskId::generate(),
                at_unix_ms,
                TaskEventKind::StateChanged {
                    from: TaskState::Queued,
                    to: TaskState::Connecting,
                },
            );
        }

        let events = buffer.drain();
        assert_eq!(events.len(), MAX_PENDING_EVENTS);
        assert_ne!(events[0].task_id(), &oldest);
        assert_eq!(events[0].at_unix_ms(), 2);
        assert_eq!(
            events[0].kind(),
            TaskEventKind::StateChanged {
                from: TaskState::Queued,
                to: TaskState::Connecting,
            }
        );
        assert!(buffer.drain().is_empty());
    }
    #[test]
    fn progress_is_coalesced_and_cannot_evict_a_terminal_event() {
        let mut buffer = TaskEventBuffer::default();
        let id = TaskId::generate();
        for time in 0..10000 {
            buffer.record(id.clone(), time, TaskEventKind::ProgressHintChanged);
        }
        assert_eq!(buffer.events.len(), 1);
        assert_eq!(buffer.events[0].at_unix_ms(), 9999);
        let terminal = TaskId::generate();
        buffer.record(
            terminal.clone(),
            10001,
            TaskEventKind::StateChanged {
                from: TaskState::Finalizing,
                to: TaskState::Completed,
            },
        );
        for time in 0..10000 {
            buffer.record(TaskId::generate(), time, TaskEventKind::ProgressHintChanged);
        }
        assert_eq!(buffer.events.len(), MAX_PENDING_EVENTS);
        assert!(
            buffer
                .drain()
                .iter()
                .any(|event| event.task_id() == &terminal)
        );
        assert!(!buffer.take_resync_required());
    }
    #[test]
    fn lifecycle_overflow_requires_snapshot_even_after_events_are_drained() {
        let mut buffer = TaskEventBuffer::default();
        for time in 0..MAX_PENDING_EVENTS + 10 {
            buffer.record(
                TaskId::generate(),
                time as i64,
                TaskEventKind::StateChanged {
                    from: TaskState::Finalizing,
                    to: TaskState::Completed,
                },
            );
        }
        assert_eq!(buffer.drain().len(), MAX_PENDING_EVENTS);
        assert!(buffer.take_resync_required());
        assert!(!buffer.take_resync_required());
    }
}
