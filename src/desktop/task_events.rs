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
}

impl TaskEventBuffer {
    pub(crate) fn push(&mut self, event: TaskEvent) {
        if self.events.len() == MAX_PENDING_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
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
}
