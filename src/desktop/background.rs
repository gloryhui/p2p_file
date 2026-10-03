//! Window lifetime, real status projection, and the menu-bar panel.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BackgroundOptions {
    #[serde(default)]
    pub close_to_tray: bool,
    #[serde(default)]
    pub launch_at_login: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum CoreState {
    #[default]
    Offline,
    Connecting,
    Online,
    Active,
    Error,
}
impl CoreState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Offline => "未配置 / 离线",
            Self::Connecting => "连接中",
            Self::Online => "在线",
            Self::Active => "传输 / 测速中",
            Self::Error => "需要处理",
        }
    }
    pub fn color(self) -> [u8; 3] {
        match self {
            Self::Offline => [120, 128, 143],
            Self::Connecting => [222, 157, 40],
            Self::Online => [39, 166, 113],
            Self::Active => [50, 117, 227],
            Self::Error => [216, 75, 75],
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum SignalState {
    #[default]
    Offline,
    Connecting,
    Online,
    Error,
}
impl SignalState {
    pub fn apply(&mut self, lifecycle: &network_state::NetworkLifecycle) {
        use network_state::NetworkLifecycle as N;
        match lifecycle {
            N::Unconfigured => *self = Self::Offline,
            N::ConnectingSignal | N::ReconnectingSignal { .. } => *self = Self::Connecting,
            N::SignalOnline => *self = Self::Online,
            N::Failed { .. } => *self = Self::Error,
            N::Disconnected { peer: None, .. } => *self = Self::Offline,
            _ => {} // A peer failure never changes the signaling state.
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct StatusSnapshot {
    pub core: CoreState,
    pub device_id: String,
    pub signal: String,
    pub connected_peers: usize,
    pub active_files: usize,
    pub queued_files: usize,
    pub bytes_per_second: u64,
    pub tunnels: usize,
    pub waiting_tunnels: usize,
    pub tunnel_errors: usize,
    pub speed_running: bool,
    pub detail: String,
}
impl StatusSnapshot {
    pub fn tooltip(&self) -> String {
        format!(
            "P2P File · {} · {} 台设备 · {} 个传输 · {} 个隧道",
            self.core.label(),
            self.connected_peers,
            self.active_files,
            self.tunnels
        )
    }
    fn project_core(&mut self, signal: SignalState, error: bool) {
        self.core = if error || signal == SignalState::Error || self.tunnel_errors > 0 {
            CoreState::Error
        } else if self.active_files > 0 || self.speed_running {
            CoreState::Active
        } else if self.connected_peers > 0 || signal == SignalState::Online {
            CoreState::Online
        } else if signal == SignalState::Connecting {
            CoreState::Connecting
        } else {
            CoreState::Offline
        };
    }
}

pub(super) struct DesktopRuntime {
    shell: Entity<DesktopShell>,
    main: gpui::WindowHandle<DesktopShell>,
    tray: Option<tray::NativeTray>,
    hidden: bool,
    panel: Option<gpui::WindowHandle<StatusPanel>>,
    snapshot: StatusSnapshot,
    quitting: bool,
}
impl gpui::Global for DesktopRuntime {}

/// Close means quit unless there is a proven usable entry point.
fn keep_running(options: BackgroundOptions, tray_available: bool) -> bool {
    options.close_to_tray && tray_available
}

pub(super) fn install(
    main: gpui::WindowHandle<DesktopShell>,
    cx: &mut App,
    background_start: bool,
) {
    let shell = main
        .update(cx, |_, _, cx| cx.entity())
        .expect("new main window");
    cx.set_global(DesktopRuntime {
        shell: shell.clone(),
        main,
        tray: None,
        hidden: false,
        panel: None,
        snapshot: StatusSnapshot::default(),
        quitting: false,
    });
    main.update(cx, |_, window, cx| {
        window.on_window_should_close(cx, |window, cx| {
            let runtime = cx.global::<DesktopRuntime>();
            let available = runtime
                .tray
                .as_ref()
                .is_some_and(tray::NativeTray::available);
            let options = runtime.shell.read(cx).settings.background;
            if keep_running(options, available) {
                match hide_window(window) {
                    Ok(()) => {
                        cx.update_global::<DesktopRuntime, _>(|runtime, _| runtime.hidden = true)
                    }
                    Err(error) => {
                        eprintln!("无法隐藏主窗口：{error}");
                        cx.global::<DesktopRuntime>()
                            .shell
                            .clone()
                            .update(cx, |shell, cx| shell.set_status(error, cx));
                    }
                }
            } else {
                request_quit(cx);
            }
            false
        });
    })
    .expect("install close handler");

    let shutdown_shell = shell.downgrade();
    cx.on_app_quit(move |cx| {
        let session = shutdown_shell
            .upgrade()
            .and_then(|shell| shell.update(cx, |shell, _| shell.network_session.take()));
        // GPUI only allows 100 ms for quit futures. Native OS termination needs
        // a synchronous bounded fallback; ordinary Quit waits off the UI thread.
        if let Some(session) = session {
            session.shutdown_and_wait();
        }
        async {}
    })
    .detach();

    #[cfg(target_os = "linux")]
    cx.spawn(async move |cx| {
        let result = cx
            .background_executor()
            .spawn(async { tray::NativeTray::new() })
            .await;
        let _ = cx.update(|cx| finish_install(result, background_start, cx));
    })
    .detach();
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    finish_install(tray::NativeTray::new(), background_start, cx);

    let timer = cx.background_executor().clone();
    cx.spawn(async move |cx| {
        loop {
            timer.timer(Duration::from_millis(200)).await;
            if cx.update(poll).is_err() {
                break;
            }
        }
    })
    .detach();
}

fn finish_install(result: Result<tray::NativeTray, String>, background_start: bool, cx: &mut App) {
    match result {
        Ok(tray) => {
            cx.update_global::<DesktopRuntime, _>(|runtime, cx| {
                let available = tray.available();
                runtime.tray = Some(tray);
                // A login launch is background even when ordinary close-to-tray
                // is disabled. Never hide the first-use password/setup screen.
                if available
                    && background_start
                    && runtime.shell.read(cx).settings.background.launch_at_login
                    && !runtime.shell.read(cx).show_settings_home
                    && !runtime.shell.read(cx).show_settings
                {
                    runtime.hidden = runtime
                        .main
                        .update(cx, |_, window, _| hide_window(window))
                        .is_ok_and(|result| result.is_ok());
                }
            });
        }
        Err(error) => {
            cx.global::<DesktopRuntime>()
                .shell
                .clone()
                .update(cx, |shell, cx| {
                    shell.set_status(format!("系统托盘不可用，保持主窗口运行：{error}"), cx);
                });
            show_main(cx, false);
        }
    }
}

fn poll(cx: &mut App) {
    let shell = cx.global::<DesktopRuntime>().shell.clone();
    let snapshot = shell.read(cx).status_snapshot();
    let mut actions = Vec::new();
    let mut restore = false;
    cx.update_global::<DesktopRuntime, _>(|runtime, cx| {
        if let Some(tray) = &mut runtime.tray {
            actions = tray.poll();
            let failed = tray.update(snapshot.clone()).is_err() || !tray.available();
            restore = runtime.hidden
                && (failed
                    || !runtime.shell.read(cx).settings.background.close_to_tray
                        && !runtime.shell.read(cx).settings.background.launch_at_login);
        }
        if runtime.snapshot != snapshot {
            runtime.snapshot = snapshot;
            if let Some(panel) = runtime.panel {
                let _ = panel.update(cx, |_, _, cx| cx.notify());
            }
        }
        let _ = cx;
    });
    if restore {
        show_main(cx, false);
    }
    for action in actions {
        match action {
            tray::TrayAction::Open => show_main(cx, false),
            tray::TrayAction::Settings => show_main(cx, true),
            tray::TrayAction::Quit => request_quit(cx),
            tray::TrayAction::Panel => toggle_panel(cx),
        }
    }
}

fn show_main(cx: &mut App, settings: bool) {
    close_panel(cx);
    let main = cx.global::<DesktopRuntime>().main;
    let _ = main.update(cx, |shell, window, cx| {
        show_window(window);
        window.activate_window();
        cx.activate(true);
        if settings {
            shell.open_settings_home(cx);
        }
        cx.notify();
    });
    cx.update_global::<DesktopRuntime, _>(|runtime, _| runtime.hidden = false);
}

pub(super) fn reopen(cx: &mut App) {
    if cx.has_global::<DesktopRuntime>() {
        show_main(cx, false);
    }
}

pub(super) fn request_quit(cx: &mut App) {
    if !cx.has_global::<DesktopRuntime>() {
        cx.quit();
        return;
    }
    let shell = cx.global::<DesktopRuntime>().shell.clone();
    if cx.global::<DesktopRuntime>().quitting {
        return;
    }
    cx.update_global::<DesktopRuntime, _>(|runtime, _| runtime.quitting = true);
    let session = shell.update(cx, |shell, cx| {
        shell.set_status("正在保存恢复状态并退出…", cx);
        shell.network_session.take()
    });
    let executor = cx.background_executor().clone();
    cx.spawn(async move |cx| {
        if let Some(session) = session {
            executor
                .spawn(async move {
                    session.shutdown_and_wait();
                })
                .await;
        }
        let _ = cx.update(|cx| cx.quit());
    })
    .detach();
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn hide_window(window: &mut Window) -> Result<(), String> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    let handle = HasWindowHandle::window_handle(window)
        .map_err(|e| e.to_string())?
        .as_raw();
    match handle {
        #[cfg(target_os = "macos")]
        RawWindowHandle::AppKit(handle) => {
            // GPUI owns the NSView and NSWindow; orderOut changes visibility only.
            unsafe {
                use objc2::{msg_send, runtime::AnyObject};
                let native: *mut AnyObject =
                    msg_send![handle.ns_view.as_ptr() as *mut AnyObject, window];
                let _: () = msg_send![native, orderOut: std::ptr::null::<AnyObject>()];
            }
            Ok(())
        }
        #[cfg(target_os = "windows")]
        RawWindowHandle::Win32(handle) => {
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
                    handle.hwnd.get() as _,
                    windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE,
                );
            }
            Ok(())
        }
        _ => Err("当前窗口系统不支持后台隐藏，保持主窗口".into()),
    }
}

fn show_window(window: &mut Window) {
    #[cfg(target_os = "linux")]
    if gpui::guess_compositor() == "X11" {
        let _ = map_x11_main(true);
    }
    #[cfg(target_os = "windows")]
    {
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        if let Ok(handle) = HasWindowHandle::window_handle(window)
            && let RawWindowHandle::Win32(handle) = handle.as_raw()
        {
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::ShowWindow(
                    handle.hwnd.get() as _,
                    windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOW,
                );
            }
        }
    }
    let _ = window;
}

#[cfg(target_os = "linux")]
fn hide_window(window: &mut Window) -> Result<(), String> {
    if gpui::guess_compositor() == "X11" {
        map_x11_main(false)
    } else {
        window.minimize_window();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn map_x11_main(show: bool) -> Result<(), String> {
    use x11rb::{
        connection::Connection,
        protocol::xproto::{AtomEnum, ConnectionExt},
    };
    // GPUI 0.2.2's X11 HasWindowHandle implementation is unimplemented. Find
    // only our main client via its PID and exact title, retaining the GPUI
    // window rather than removing the last window (which stops its event loop).
    let (connection, screen) = x11rb::connect(None).map_err(|e| e.to_string())?;
    let root = connection.setup().roots[screen].root;
    let atom = |name: &[u8]| -> Result<u32, String> {
        Ok(connection
            .intern_atom(false, name)
            .map_err(|e| e.to_string())?
            .reply()
            .map_err(|e| e.to_string())?
            .atom)
    };
    let pid_atom = atom(b"_NET_WM_PID")?;
    let clients_atom = atom(b"_NET_CLIENT_LIST")?;
    let clients = connection
        .get_property(false, root, clients_atom, AtomEnum::WINDOW, 0, 4096)
        .map_err(|e| e.to_string())?
        .reply()
        .map_err(|e| e.to_string())?;
    let mut pending: std::collections::VecDeque<u32> =
        clients.value32().into_iter().flatten().collect();
    pending.extend(
        connection
            .query_tree(root)
            .map_err(|e| e.to_string())?
            .reply()
            .map_err(|e| e.to_string())?
            .children,
    );
    let mut visited = HashSet::new();
    while let Some(candidate) = pending.pop_front() {
        if visited.len() >= 4096 {
            break;
        }
        if !visited.insert(candidate) {
            continue;
        }
        let pid = connection
            .get_property(false, candidate, pid_atom, AtomEnum::CARDINAL, 0, 1)
            .map_err(|e| e.to_string())?
            .reply();
        if let Ok(pid) = pid
            && pid.value32().and_then(|mut values| values.next()) == Some(std::process::id())
        {
            let title = connection
                .get_property(false, candidate, AtomEnum::WM_NAME, AtomEnum::ANY, 0, 32)
                .map_err(|e| e.to_string())?
                .reply();
            if title.is_ok_and(|title| title.value == b"P2P File") {
                let request = if show {
                    connection.map_window(candidate)
                } else {
                    connection.unmap_window(candidate)
                }
                .map_err(|e| e.to_string())?;
                request.check().map_err(|e| e.to_string())?;
                return connection.flush().map_err(|e| e.to_string());
            }
        }
        // Window managers can reparent a hidden client into a frame; without
        // EWMH, root descendants are the fallback. Never modify other windows.
        if let Ok(request) = connection.query_tree(candidate)
            && let Ok(tree) = request.reply()
        {
            pending.extend(
                tree.children
                    .into_iter()
                    .take(4096usize.saturating_sub(visited.len())),
            );
        }
    }
    Err("未找到本进程的主窗口，保持现有窗口".into())
}

impl DesktopShell {
    fn status_snapshot(&self) -> StatusSnapshot {
        let mut snapshot = StatusSnapshot {
            device_id: self
                .local_short_id
                .map(|id| id.display())
                .or_else(|| self.identity_id.clone())
                .unwrap_or_else(|| "身份不可用".into()),
            signal: self.network_status.to_string(),
            connected_peers: self
                .peer_states
                .values()
                .filter(|state| state.is_connected())
                .count(),
            active_files: self.background_files.0,
            queued_files: self.background_files.1,
            bytes_per_second: self.background_files.2,
            speed_running: self
                .speed_views
                .0
                .values()
                .any(|view| view.snapshot.status == speed::SpeedStatus::Running),
            detail: self.status.to_string(),
            ..Default::default()
        };
        for state in self.tunnel_states.values() {
            match state {
                session::TunnelRuntimeState::Running => snapshot.tunnels += 1,
                session::TunnelRuntimeState::WaitingAuthorization
                | session::TunnelRuntimeState::Starting => snapshot.waiting_tunnels += 1,
                session::TunnelRuntimeState::Error(_) => snapshot.tunnel_errors += 1,
                session::TunnelRuntimeState::Stopped => {}
            }
        }
        snapshot.project_core(
            self.signal_state,
            self.identity_id.is_none() || self.transfer_service.is_none(),
        );
        snapshot
    }

    fn change_background_option(&mut self, login: bool, cx: &mut Context<Self>) {
        if self.is_saving_settings || !self.can_save_settings {
            return;
        }
        let old = self.settings.background;
        let mut next = old;
        if login {
            next.launch_at_login = !next.launch_at_login;
        } else {
            next.close_to_tray = !next.close_to_tray;
        }
        let path = self.config_file.clone();
        self.is_saving_settings = true;
        let executor = cx.background_executor().clone();
        cx.spawn(async move |shell, cx| {
            let result = executor
                .spawn(async move {
                    if login {
                        autostart::apply(next.launch_at_login)?;
                    }
                    if let Err(error) = DesktopConfig::save_background_options(&path, next) {
                        if login {
                            autostart::apply(old.launch_at_login).map_err(|rollback| {
                                format!("{error}；启动项回退失败：{rollback}")
                            })?;
                        }
                        return Err(error.to_string());
                    }
                    Ok::<_, String>(())
                })
                .await;
            let _ = shell.update(cx, |shell, cx| {
                shell.is_saving_settings = false;
                match result {
                    Ok(()) => {
                        shell.settings.background = next;
                        shell.set_status("后台设置已保存；登录启动的修改从下次登录生效", cx);
                    }
                    Err(error) => shell.set_status(format!("后台设置未保存：{error}"), cx),
                }
            });
        })
        .detach();
    }

    pub(super) fn background_card(&self, cx: &mut Context<Self>) -> gpui::Div {
        let options = self.settings.background;
        ui_components::card().child(ui_components::section_header("◉", "后台运行", "后台保持连接；重启后的文件仍需手动继续"))
            .child(div().flex().gap_2()
                .child(ui_components::secondary_button(if options.close_to_tray { "✓ 关闭窗口后后台运行" } else { "关闭窗口后后台运行：关" }, !self.is_saving_settings)
                    .on_mouse_up(MouseButton::Left, cx.listener(|shell, _: &MouseUpEvent, _, cx| shell.change_background_option(false, cx))))
                .child(ui_components::secondary_button(if options.launch_at_login { "✓ 登录系统时启动" } else { "登录系统时启动：关" }, !self.is_saving_settings)
                    .on_mouse_up(MouseButton::Left, cx.listener(|shell, _: &MouseUpEvent, _, cx| shell.change_background_option(true, cx)))))
            .child(div().text_xs().text_color(rgb(ui_theme::TEXT_SECONDARY)).child("从菜单栏 / 托盘打开主窗口或退出。Linux Wayland 关闭时最小化；无托盘时正常退出。"))
    }
}

fn close_panel(cx: &mut App) {
    let panel = cx.update_global::<DesktopRuntime, _>(|runtime, _| runtime.panel.take());
    if let Some(panel) = panel {
        let _ = panel.update(cx, |_, window, _| window.remove_window());
    }
}

fn toggle_panel(cx: &mut App) {
    let runtime = cx.global::<DesktopRuntime>();
    if runtime.panel.is_some_and(|panel| panel.read(cx).is_ok()) {
        close_panel(cx);
        return;
    }
    #[cfg(target_os = "macos")]
    let anchor = cx
        .global::<DesktopRuntime>()
        .tray
        .as_ref()
        .and_then(|tray| tray.anchor());
    #[cfg(not(target_os = "macos"))]
    let anchor: Option<(u32, f32, f32)> = None;
    let (bounds, display_id) = if let Some((id, x, y)) = anchor {
        let display = cx
            .displays()
            .into_iter()
            .find(|display| u32::from(display.id()) == id);
        let display_id = display.as_ref().map(|display| display.id());
        let width = display
            .map(|display| f32::from(display.bounds().size.width))
            .unwrap_or(800.);
        let left = (x - 320.).clamp(0., (width - 360.).max(0.));
        (
            Bounds::new(point(px(left), px(y + 4.)), size(px(360.), px(390.))),
            display_id,
        )
    } else {
        (Bounds::centered(None, size(px(360.), px(390.)), cx), None)
    };
    match cx.open_window(
        WindowOptions {
            titlebar: None,
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            display_id,
            kind: gpui::WindowKind::PopUp,
            is_resizable: false,
            is_minimizable: false,
            is_movable: false,
            ..Default::default()
        },
        |window, cx| {
            cx.new(|cx| {
                cx.observe_window_activation(window, |_, window, _| {
                    if !window.is_window_active() {
                        window.remove_window();
                    }
                })
                .detach();
                StatusPanel
            })
        },
    ) {
        Ok(panel) => {
            cx.update_global::<DesktopRuntime, _>(|runtime, _| runtime.panel = Some(panel));
        }
        Err(_) => show_main(cx, false),
    }
}

struct StatusPanel;
impl Render for StatusPanel {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let snapshot = cx.global::<DesktopRuntime>().snapshot.clone();
        let color = snapshot.core.color();
        let color = ((color[0] as u32) << 16) | ((color[1] as u32) << 8) | color[2] as u32;
        let rows = [
            ("本机设备", snapshot.device_id.clone()),
            ("信令", snapshot.signal.clone()),
            ("已认证设备", format!("{} 台", snapshot.connected_peers)),
            (
                "文件传输",
                format!(
                    "{} 个活动 · {} 个排队 · {:.1} MiB/s",
                    snapshot.active_files,
                    snapshot.queued_files,
                    snapshot.bytes_per_second as f64 / 1_048_576.
                ),
            ),
            (
                "TCP 隧道",
                format!(
                    "{} 个运行 · {} 个等待 · {} 个异常",
                    snapshot.tunnels, snapshot.waiting_tunnels, snapshot.tunnel_errors
                ),
            ),
            (
                "测速",
                if snapshot.speed_running {
                    "进行中".into()
                } else {
                    "空闲".into()
                },
            ),
        ];
        div()
            .size_full()
            .bg(rgb(ui_theme::PAGE_BG))
            .p(px(18.))
            .flex()
            .flex_col()
            .gap_3()
            .text_color(rgb(ui_theme::TEXT))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("P2P File"),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(color))
                            .child(format!("● {}", snapshot.core.label())),
                    ),
            )
            .children(rows.into_iter().map(|(label, value)| {
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .text_xs()
                    .child(
                        div()
                            .w(px(76.))
                            .flex_shrink_0()
                            .text_color(rgb(ui_theme::TEXT_SECONDARY))
                            .child(label),
                    )
                    .child(div().flex_1().min_w_0().truncate().child(value))
            }))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .overflow_hidden()
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child(snapshot.detail),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        ui_components::secondary_button("打开主窗口", true).on_mouse_up(
                            MouseButton::Left,
                            cx.listener(|_, _: &MouseUpEvent, _, cx| {
                                cx.defer(|cx| show_main(cx, false));
                            }),
                        ),
                    )
                    .child(ui_components::secondary_button("设置", true).on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|_, _: &MouseUpEvent, _, cx| {
                            cx.defer(|cx| show_main(cx, true));
                        }),
                    ))
                    .child(ui_components::secondary_button("退出", true).on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|_, _: &MouseUpEvent, _, cx| request_quit(cx)),
                    )),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn close_requires_opt_in_and_a_usable_tray() {
        assert!(!keep_running(BackgroundOptions::default(), true));
        let enabled = BackgroundOptions {
            close_to_tray: true,
            launch_at_login: false,
        };
        assert!(keep_running(enabled, true));
        assert!(!keep_running(enabled, false));
    }
    #[test]
    fn signal_and_peer_status_are_independent_and_active_business_survives_signal_loss() {
        let mut signal = SignalState::Online;
        signal.apply(&network_state::NetworkLifecycle::Disconnected {
            peer: Some(NodeId::from_hex("01010101010101010101010101010101").unwrap()),
            detail: "peer down".into(),
        });
        assert_eq!(signal, SignalState::Online);
        let mut snapshot = StatusSnapshot {
            connected_peers: 1,
            ..Default::default()
        };
        snapshot.project_core(SignalState::Connecting, false);
        assert_eq!(snapshot.core, CoreState::Online);
        snapshot.active_files = 1;
        snapshot.project_core(SignalState::Offline, false);
        assert_eq!(snapshot.core, CoreState::Active);
        snapshot.tunnel_errors = 1;
        snapshot.project_core(signal, false);
        assert_eq!(snapshot.core, CoreState::Error);
    }
    #[test]
    fn every_core_state_has_a_distinct_monochrome_menu_bar_icon() {
        let icons: Vec<_> = [
            CoreState::Offline,
            CoreState::Connecting,
            CoreState::Online,
            CoreState::Active,
            CoreState::Error,
        ]
        .into_iter()
        .map(|state| tray::icon_rgba(state, true))
        .collect();
        for (i, icon) in icons.iter().enumerate() {
            assert_eq!(icon.len(), 32 * 32 * 4);
            assert!(icons[i + 1..].iter().all(|other| icon != other));
        }
    }
}
