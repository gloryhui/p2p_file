//! One atomic admission boundary for selected/scanning files, reserved streams
//! and speed leases. Permits cover cleanup as well as the visible operation.
use super::{task_model::TaskId, transfer_files::failure};
use crate::{error::Result, identity::NodeId};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::sync::watch;

#[derive(Clone)]
pub(crate) struct Activity {
    state: Arc<Mutex<State>>,
    changed: watch::Sender<u64>,
}
#[derive(Default)]
pub(crate) struct State {
    peers: HashMap<NodeId, Entry>,
}
#[derive(Default)]
struct Entry {
    files: usize,
    speed: Option<TaskId>,
}
pub(crate) struct FilePermit {
    activity: Activity,
    peer: NodeId,
}
pub(crate) struct SpeedPermit {
    activity: Activity,
    peer: NodeId,
    id: TaskId,
}
impl Activity {
    pub fn new(changed: watch::Sender<u64>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            changed,
        }
    }
    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }
    pub fn file(&self, peer: NodeId) -> Result<FilePermit> {
        self.lock().add_file(peer)?;
        Ok(self.file_permit(peer))
    }
    // Caller already incremented under the shared admission lock.
    pub fn file_permit(&self, peer: NodeId) -> FilePermit {
        FilePermit {
            activity: self.clone(),
            peer,
        }
    }
    pub fn speed(&self, peer: NodeId, id: TaskId) -> Result<SpeedPermit> {
        let mut state = self.lock();
        let entry = state.peers.entry(peer).or_default();
        if entry.files != 0 || entry.speed.is_some() {
            return Err(failure("文件或测速正在进行，请先暂停文件或取消测速"));
        }
        entry.speed = Some(id.clone());
        Ok(SpeedPermit {
            activity: self.clone(),
            peer,
            id,
        })
    }
}
impl State {
    pub fn can_speed(&self, peer: NodeId) -> bool {
        self.peers
            .get(&peer)
            .is_none_or(|e| e.files == 0 && e.speed.is_none())
    }
    pub fn speed_active(&self, peer: NodeId) -> bool {
        self.peers.get(&peer).is_some_and(|e| e.speed.is_some())
    }
    pub fn add_file(&mut self, peer: NodeId) -> Result<()> {
        let entry = self.peers.entry(peer).or_default();
        if entry.speed.is_some() {
            return Err(failure("测速正在进行，不能启动文件任务"));
        }
        entry.files = entry
            .files
            .checked_add(1)
            .ok_or_else(|| failure("文件资源计数超限"))?;
        Ok(())
    }
    fn prune(&mut self, peer: NodeId) {
        if self
            .peers
            .get(&peer)
            .is_some_and(|e| e.files == 0 && e.speed.is_none())
        {
            self.peers.remove(&peer);
        }
    }
}
impl Drop for FilePermit {
    fn drop(&mut self) {
        {
            let mut state = self.activity.lock();
            let entry = state.peers.get_mut(&self.peer).unwrap();
            entry.files -= 1;
            state.prune(self.peer);
        }
        self.activity
            .changed
            .send_modify(|v| *v = v.wrapping_add(1));
    }
}
impl Drop for SpeedPermit {
    fn drop(&mut self) {
        {
            let mut state = self.activity.lock();
            if let Some(entry) = state.peers.get_mut(&self.peer)
                && entry.speed.as_ref() == Some(&self.id)
            {
                entry.speed = None;
            }
            state.prune(self.peer);
        }
        self.activity
            .changed
            .send_modify(|v| *v = v.wrapping_add(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    #[test]
    fn file_and_speed_admission_is_atomic_per_peer_and_cleanup_releases_it() {
        let (changed, _) = watch::channel(0);
        let activity = Activity::new(changed);
        let a = Identity::generate().node_id();
        let b = Identity::generate().node_id();
        let file = activity.file(a).unwrap();
        assert!(activity.speed(a, TaskId::generate()).is_err());
        let speed = activity.speed(b, TaskId::generate()).unwrap();
        assert!(activity.file(b).is_err());
        assert!(activity.speed(b, TaskId::generate()).is_err());
        drop(file);
        drop(speed);
        let speed = activity.speed(a, TaskId::generate()).unwrap();
        let file = activity.file(b).unwrap();
        drop(speed);
        drop(file);
        assert!(activity.lock().peers.is_empty());
    }
}
