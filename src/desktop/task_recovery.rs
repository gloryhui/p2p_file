//! Startup interruption and explicit, TaskId-only recovery lookup.
//!
//! Recovery lookup returns only the already stored local binding. It accepts
//! no remote path and never queues a task by itself.

use std::path::PathBuf;

use super::{
    task_model::{
        ManifestIdentity, PeerId, TaskDiagnostic, TaskDirection, TaskErrorCode, TaskId,
        TaskModelError, TaskRecord, TaskState, system_time_unix_ms,
    },
    task_store::{TaskStore, TaskStoreError},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StartupRecoveryReport {
    interrupted_task_ids: Vec<TaskId>,
}

impl StartupRecoveryReport {
    pub(crate) fn interrupted_task_ids(&self) -> &[TaskId] {
        &self.interrupted_task_ids
    }
}

pub(crate) fn recover_startup(
    tasks: &mut [TaskRecord],
) -> Result<StartupRecoveryReport, TaskModelError> {
    let now = system_time_unix_ms()?;
    let mut interrupted_task_ids = Vec::new();

    for task in tasks {
        if task.state().needs_startup_recovery() {
            task.transition_to(
                TaskState::Interrupted,
                Some(TaskDiagnostic::new(
                    TaskErrorCode::ApplicationRestarted,
                    false,
                )),
                now,
            )?;
            interrupted_task_ids.push(task.task_id_owned());
        }
    }

    Ok(StartupRecoveryReport {
        interrupted_task_ids,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SenderRecovery {
    task_id: TaskId,
    peer_id: PeerId,
    source_path: PathBuf,
    manifest_identity: ManifestIdentity,
    state: TaskState,
}

impl SenderRecovery {
    pub(crate) fn task_id(&self) -> &TaskId {
        &self.task_id
    }
    #[allow(dead_code)] // Consumed by the later peer-session task adapter.
    pub(crate) fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
    pub(crate) fn source_path(&self) -> &std::path::Path {
        &self.source_path
    }
    #[allow(dead_code)] // The sender executor binds this manifest in the later task.
    pub(crate) fn manifest_identity(&self) -> &ManifestIdentity {
        &self.manifest_identity
    }
    pub(crate) fn state(&self) -> TaskState {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiverRecovery {
    task_id: TaskId,
    peer_id: PeerId,
    receive_root: PathBuf,
    manifest_identity: ManifestIdentity,
    state: TaskState,
}

impl ReceiverRecovery {
    pub(crate) fn task_id(&self) -> &TaskId {
        &self.task_id
    }
    pub(crate) fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }
    pub(crate) fn receive_root(&self) -> &std::path::Path {
        &self.receive_root
    }
    #[allow(dead_code)] // The receiver executor binds this manifest in the later task.
    pub(crate) fn manifest_identity(&self) -> &ManifestIdentity {
        &self.manifest_identity
    }
    pub(crate) fn state(&self) -> TaskState {
        self.state
    }
}

pub(crate) fn sender_recovery(
    store: &TaskStore,
    task_id: &TaskId,
) -> Result<SenderRecovery, TaskStoreError> {
    let task = store.task(task_id)?;
    if task.direction() != TaskDirection::Send {
        return Err(TaskStoreError::Model(TaskModelError::WrongDirection));
    }
    ensure_explicitly_recoverable(&task)?;
    Ok(SenderRecovery {
        task_id: task.task_id_owned(),
        peer_id: task.peer_id().clone(),
        source_path: task.local_path().to_path_buf(),
        manifest_identity: task.manifest_identity().clone(),
        state: task.state(),
    })
}

pub(crate) fn receiver_recovery(
    store: &TaskStore,
    task_id: &TaskId,
) -> Result<ReceiverRecovery, TaskStoreError> {
    let task = store.task(task_id)?;
    if task.direction() != TaskDirection::Receive {
        return Err(TaskStoreError::Model(TaskModelError::WrongDirection));
    }
    ensure_explicitly_recoverable(&task)?;
    Ok(ReceiverRecovery {
        task_id: task.task_id_owned(),
        peer_id: task.peer_id().clone(),
        receive_root: task.local_path().to_path_buf(),
        manifest_identity: task.manifest_identity().clone(),
        state: task.state(),
    })
}

fn ensure_explicitly_recoverable(task: &TaskRecord) -> Result<(), TaskStoreError> {
    let state_is_recoverable = matches!(task.state(), TaskState::Paused | TaskState::Interrupted)
        || (task.state() == TaskState::Failed
            && task.diagnostic().is_some_and(TaskDiagnostic::is_retryable));

    if state_is_recoverable {
        Ok(())
    } else {
        Err(TaskStoreError::Model(TaskModelError::NotRecoverable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn record() -> TaskRecord {
        #[cfg(windows)]
        let path = PathBuf::from(r"C:\tmp\local-source.bin");
        #[cfg(not(windows))]
        let path = PathBuf::from("/tmp/local-source.bin");
        TaskRecord::new_sender(
            PeerId::from_node_id(crate::identity::NodeId::from_public_key(
                &Identity::generate().public_key(),
            )),
            path,
            ManifestIdentity::blake3([3; 32], 4, 4).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn startup_interrupts_active_states_but_preserves_paused_and_terminal_states() {
        let mut active = record();
        let id = active.task_id_owned();
        let report = recover_startup(std::slice::from_mut(&mut active)).unwrap();
        assert_eq!(active.state(), TaskState::Interrupted);
        assert_eq!(
            active.diagnostic().unwrap().code(),
            TaskErrorCode::ApplicationRestarted
        );
        assert_eq!(report.interrupted_task_ids(), &[id]);

        let mut paused = record();
        paused.transition_to(TaskState::Queued, None, 2).unwrap();
        paused
            .transition_to(TaskState::Connecting, None, 3)
            .unwrap();
        paused.transition_to(TaskState::Pausing, None, 4).unwrap();
        paused.transition_to(TaskState::Paused, None, 5).unwrap();
        let mut completed = record();
        completed.transition_to(TaskState::Queued, None, 2).unwrap();
        completed
            .transition_to(TaskState::Connecting, None, 3)
            .unwrap();
        completed
            .transition_to(TaskState::Negotiating, None, 4)
            .unwrap();
        completed
            .transition_to(TaskState::Transferring, None, 5)
            .unwrap();
        completed
            .transition_to(TaskState::Finalizing, None, 6)
            .unwrap();
        completed
            .transition_to(TaskState::Completed, None, 7)
            .unwrap();
        let mut failed = record();
        failed
            .transition_to(
                TaskState::Failed,
                Some(TaskDiagnostic::new(TaskErrorCode::SourceUnavailable, false)),
                8,
            )
            .unwrap();

        let report =
            recover_startup(&mut [paused.clone(), completed.clone(), failed.clone()]).unwrap();
        assert!(report.interrupted_task_ids().is_empty());
    }
}
