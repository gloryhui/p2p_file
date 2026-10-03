//! Native entry points only; all actions are handled by the existing GPUI shell.
use super::background::{CoreState, StatusSnapshot};
use std::sync::mpsc::Receiver;
#[cfg(target_os = "linux")]
use std::sync::mpsc::SyncSender;

#[derive(Clone, Copy, Debug)]
pub(super) enum TrayAction {
    Open,
    Settings,
    Quit,
    Panel,
}

pub(super) struct NativeTray {
    #[cfg(target_os = "linux")]
    handle: ksni::blocking::Handle<LinuxTray>,
    #[cfg(target_os = "linux")]
    available: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    icon: tray_icon::TrayIcon,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    status: tray_icon::menu::MenuItem,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    menu_actions: Vec<(tray_icon::menu::MenuId, TrayAction)>,
    events: Receiver<TrayAction>,
    last: Option<StatusSnapshot>,
}

impl NativeTray {
    pub fn new() -> Result<Self, String> {
        let (sender, events) = std::sync::mpsc::sync_channel(16);
        #[cfg(target_os = "linux")]
        {
            use ksni::blocking::TrayMethods;
            let available = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let handle = LinuxTray {
                sender,
                available: available.clone(),
                snapshot: StatusSnapshot::default(),
            }
            .spawn()
            .map_err(|e| e.to_string())?;
            Ok(Self {
                handle,
                available,
                events,
                last: None,
            })
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            use tray_icon::{
                TrayIconBuilder,
                menu::{Menu, MenuItem},
            };
            let menu = Menu::new();
            let status = MenuItem::new("P2P File · 正在启动", false, None);
            menu.append(&status).map_err(|e| e.to_string())?;
            let mut menu_actions = Vec::new();
            for (label, action) in [
                ("状态面板", TrayAction::Panel),
                ("打开主窗口", TrayAction::Open),
                ("设置", TrayAction::Settings),
                ("退出 P2P File", TrayAction::Quit),
            ] {
                let item = MenuItem::new(label, true, None);
                menu_actions.push((item.id().clone(), action));
                menu.append(&item).map_err(|e| e.to_string())?;
            }
            let icon = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("P2P File · 正在启动")
                .with_icon(native_icon(CoreState::Offline)?)
                .with_icon_as_template(cfg!(target_os = "macos"))
                .with_menu_on_left_click(false)
                .build()
                .map_err(|e| e.to_string())?;
            let _ = sender; // Native events are emitted on the application event loop.
            Ok(Self {
                icon,
                status,
                menu_actions,
                events,
                last: None,
            })
        }
    }
    pub fn available(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.available.load(std::sync::atomic::Ordering::Acquire) && !self.handle.is_closed()
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            true
        }
    }
    pub fn poll(&self) -> Vec<TrayAction> {
        let actions: Vec<_> = self.events.try_iter().take(16).collect();
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent, menu::MenuEvent};
            let mut actions = actions;
            for event in TrayIconEvent::receiver().try_iter().take(16) {
                if let TrayIconEvent::Click {
                    id,
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                    && id == *self.icon.id()
                {
                    actions.push(if cfg!(target_os = "macos") {
                        TrayAction::Panel
                    } else {
                        TrayAction::Open
                    });
                }
            }
            for event in MenuEvent::receiver().try_iter().take(16) {
                if let Some((_, action)) = self.menu_actions.iter().find(|(id, _)| *id == event.id)
                {
                    actions.push(*action);
                }
            }
            actions
        }
        #[cfg(target_os = "linux")]
        {
            actions
        }
    }
    pub fn update(&mut self, snapshot: StatusSnapshot) -> Result<(), String> {
        if self.last.as_ref() == Some(&snapshot) {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            let snapshot = snapshot.clone();
            self.handle.update(|tray| tray.snapshot = snapshot);
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            self.icon
                .set_tooltip(Some(snapshot.tooltip()))
                .map_err(|e| e.to_string())?;
            self.status
                .set_text(format!("P2P File · {}", snapshot.core.label()));
            if self
                .last
                .as_ref()
                .is_none_or(|last| last.core != snapshot.core)
            {
                self.icon
                    .set_icon(Some(native_icon(snapshot.core)?))
                    .map_err(|e| e.to_string())?;
            }
        }
        self.last = Some(snapshot);
        Ok(())
    }
    #[cfg(target_os = "macos")]
    pub fn anchor(&self) -> Option<(u32, f32, f32)> {
        // NSWindow/NSScreen frames are logical Cocoa coordinates, so mixed DPI
        // never depends on the display hosting the unrelated main window.
        let marker = objc2::MainThreadMarker::new()?;
        let native = self.icon.ns_status_item()?.button(marker)?.window()?;
        let screen = native.screen()?;
        let frame = native.frame();
        let screen_frame = screen.frame();
        let display_id: u32 = unsafe {
            use objc2::{class, msg_send, runtime::AnyObject};
            let description: *mut AnyObject = msg_send![&*screen, deviceDescription];
            let key: *mut AnyObject =
                msg_send![class!(NSString), stringWithUTF8String: c"NSScreenNumber".as_ptr()];
            let number: *mut AnyObject = msg_send![description, objectForKey: key];
            if number.is_null() {
                return None;
            }
            msg_send![number, unsignedIntValue]
        };
        Some((
            display_id,
            (frame.origin.x - screen_frame.origin.x) as f32,
            (screen_frame.size.height - (frame.origin.y - screen_frame.origin.y)) as f32,
        ))
    }
}

#[cfg(target_os = "linux")]
impl Drop for NativeTray {
    fn drop(&mut self) {
        let _ = self.handle.shutdown();
    }
}

/// A compact two-node link, with a distinct state mark even in template mode.
pub(super) fn icon_rgba(core: CoreState, template: bool) -> Vec<u8> {
    let mut data = vec![0; 32 * 32 * 4];
    let color = if template { [0, 0, 0] } else { core.color() };
    for y in 0..32i32 {
        for x in 0..32i32 {
            let node = [(8, 16), (24, 16)].iter().any(|(cx, cy)| {
                let d = (x - cx).pow(2) + (y - cy).pow(2);
                (9..=25).contains(&d)
            });
            let link = (11..=21).contains(&x) && (15..=17).contains(&y);
            let mark = match core {
                CoreState::Offline => (13..=19).contains(&x) && (26..=27).contains(&y),
                CoreState::Connecting => {
                    ((13..=14).contains(&x) || (18..=19).contains(&x)) && (25..=28).contains(&y)
                }
                CoreState::Online => (x - 16).pow(2) + (y - 27).pow(2) <= 5,
                CoreState::Active => (x == 15 || x == 17) && (24..=29).contains(&y),
                CoreState::Error => (15..=17).contains(&x) && ((23..=26).contains(&y) || y == 29),
            };
            if node || link || mark {
                let i = ((y * 32 + x) * 4) as usize;
                data[i..i + 4].copy_from_slice(&[color[0], color[1], color[2], 255]);
            }
        }
    }
    data
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn native_icon(core: CoreState) -> Result<tray_icon::Icon, String> {
    tray_icon::Icon::from_rgba(icon_rgba(core, cfg!(target_os = "macos")), 32, 32)
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxTray {
    sender: SyncSender<TrayAction>,
    available: std::sync::Arc<std::sync::atomic::AtomicBool>,
    snapshot: StatusSnapshot,
}
#[cfg(target_os = "linux")]
impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        "p2p-file".into()
    }
    fn title(&self) -> String {
        self.snapshot.tooltip()
    }
    #[allow(clippy::chunks_exact_to_as_chunks)] // Keep Rust 1.85 compatibility.
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let mut data = icon_rgba(self.snapshot.core, false);
        for pixel in data.chunks_exact_mut(4) {
            pixel.rotate_right(1);
        } // SNI requires ARGB.
        vec![ksni::Icon {
            width: 32,
            height: 32,
            data,
        }]
    }
    fn activate(&mut self, _: i32, _: i32) {
        let _ = self.sender.try_send(TrayAction::Open);
    }
    fn watcher_online(&self) {
        self.available
            .store(true, std::sync::atomic::Ordering::Release);
    }
    fn watcher_offline(&self, _: ksni::OfflineReason) -> bool {
        self.available
            .store(false, std::sync::atomic::Ordering::Release);
        true
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;
        let mut items = vec![
            StandardItem {
                label: self.snapshot.tooltip(),
                enabled: false,
                ..Default::default()
            }
            .into(),
        ];
        for (label, action) in [
            ("状态面板", TrayAction::Panel),
            ("打开主窗口", TrayAction::Open),
            ("设置", TrayAction::Settings),
            ("退出 P2P File", TrayAction::Quit),
        ] {
            items.push(
                StandardItem {
                    label: label.into(),
                    activate: Box::new(move |tray: &mut Self| {
                        let _ = tray.sender.try_send(action);
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }
        items
    }
}
