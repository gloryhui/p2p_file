//! Native GPUI product interface backed by the authenticated desktop session.
//! Domain snapshots are projected off the UI thread; displayed completion
//! comes from persistent receiver receipts, never from command submission.
//!
//! TextField and TextFieldElement are adapted from
//! gpui v0.2.2/examples/input.rs (Apache-2.0, Zed Industries, Inc.). The
//! adaptation changes the names, styling, and application wiring, and adds the
//! T001 shell state/path-picker boundaries; it is not presented as original
//! MIT-licensed application code. See docs/gpui-mvp/THIRD_PARTY_NOTICES.md.

mod activity;
mod auto_resume;
mod autostart;
mod background;
mod bandwidth;
pub(in crate::desktop) mod config;
mod diagnostics;
mod drop_send;
#[cfg(test)]
mod e2e;
mod files;
mod frame_budget;
pub(in crate::desktop) mod instance_lock;
mod network_state;
mod notifications;
#[allow(dead_code)] // T005 wire guards are consumed by transfer/speed business in T006-T009.
mod protocol;
mod publish;
mod queue;
mod remote_auth;
pub(crate) mod secure_fs;
mod session;
mod space_budget;
mod speed;
mod task_details;
#[allow(dead_code)] // Task list consumers arrive in later GPUI task integrations.
mod task_events;
#[allow(dead_code)] // T003 establishes the domain model before transfer consumers exist.
mod task_model;
#[allow(dead_code)] // Explicit recovery APIs are consumed by later task execution work.
mod task_recovery;
#[allow(dead_code)] // Durable mutation API is intentionally staged ahead of its UI consumer.
mod task_store;
mod transfer;
mod transfer_files;
mod tray;
mod trusted_devices;
mod tunnel;
mod ui;
mod ui_model;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use std::{net::SocketAddr, ops::Range, path::PathBuf};

use crate::discovery::short_id::ShortId;
use crate::identity::{Identity, NodeId};
use config::{
    AllowedForwardTarget, AppPaths, ConfigError, DesktopConfig, SettingsDraft, SpeedtestDirection,
    TunnelRule,
};
use instance_lock::InstanceLock;
use remote_auth::{RemoteVerifier, SecretPassword};
use task_store::TaskStore;
use ui::{components as ui_components, theme as ui_theme};

use gpui::{
    App, Application, Bounds, ClipboardItem, Context, CursorStyle, ElementId, ElementInputHandler,
    Entity, EntityInputHandler, FocusHandle, Focusable, GlobalElementId, KeyBinding, LayoutId,
    MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent, PaintQuad, PathPromptOptions,
    Pixels, Point, PromptButton, PromptLevel, ShapedLine, SharedString, Style, TextRun,
    UTF16Selection, UnderlineStyle, Window, WindowBounds, WindowOptions, actions, div, fill, hsla,
    point, prelude::*, px, relative, rgb, rgba, size, white,
};
use unicode_segmentation::UnicodeSegmentation;

actions!(
    desktop_shell,
    [
        Backspace,
        Delete,
        Left,
        Right,
        SelectLeft,
        SelectRight,
        SelectAll,
        Home,
        End,
        ShowCharacterPalette,
        Paste,
        Cut,
        Copy,
        ChooseFiles,
        ChooseFolder,
        ChooseReceiveDirectory,
        Quit,
        ConnectPeer,
        SaveSettings,
        StartSpeed,
        CancelSpeed,
        ToggleSettings,
        PauseSelected,
        ResumeSelected,
        NextField,
        PreviousField,
        CopyIdentity,
        NextTask,
        PreviousTask,
        ExpandGroups,
        CycleDirection,
        CycleDuration,
        CycleConcurrency,
    ]
);

struct DesktopStartup {
    instance_lock: InstanceLock,
    task_store: Option<TaskStore>,
    task_store_status: String,
    identity_id: Option<String>,
    identity: Option<Identity>,
    identity_status: String,
    config_file: PathBuf,
    settings: SettingsDraft,
    config_note: String,
    can_save_settings: bool,
    has_saved_network_config: bool,
    initial_password: Option<SecretPassword>,
}

impl DesktopStartup {
    fn load() -> Result<Self, String> {
        let paths = AppPaths::discover().map_err(|error| error.to_string())?;
        config::ensure_private_app_dir(&paths.config_dir)
            .map_err(|error| format!("无法准备配置目录：{error}"))?;
        config::ensure_private_app_dir(&paths.data_dir)
            .map_err(|error| format!("无法准备应用数据目录：{error}"))?;
        let instance_lock = InstanceLock::acquire(&paths.instance_lock_file())
            .map_err(|error| error.to_string())?;

        let (task_store, task_store_status) =
            match TaskStore::open(&paths.data_dir.join("tasks.json")) {
                Ok((store, recovery)) => {
                    let interrupted = recovery.interrupted_task_ids().len();
                    let status = if interrupted == 0 {
                        "本机任务记录已就绪".to_owned()
                    } else {
                        format!("上次退出时有 {interrupted} 个任务中断；等待用户选择后续操作")
                    };
                    (Some(store), status)
                }
                Err(error) => (None, format!("任务记录不可用，原文件已保留：{error}")),
            };

        let (identity, identity_id, identity_status) =
            match Identity::load_or_create(&paths.identity_file()) {
                Ok(identity) => (
                    Some(identity.clone()),
                    Some(identity.node_id().to_hex()),
                    "本机身份已就绪".to_owned(),
                ),
                Err(error) => (None, None, format!("本机身份不可用：{error}")),
            };

        let config_file = paths.config_file();
        let defaults = || SettingsDraft::defaults(paths.downloads_dir.clone());
        let (mut settings, mut config_note, can_save_settings, has_saved_network_config) =
            match DesktopConfig::load(&config_file) {
                Ok(Some(config)) => {
                    let has_network = config.has_network_config();
                    let (settings, note, can_save) = config::restore_saved_settings(config);
                    (settings, note, can_save, has_network)
                }
                Ok(None) => {
                    let note = if paths.downloads_dir.is_some() {
                        "尚未保存信令设置；请填写主机和端口".to_owned()
                    } else {
                        "未找到系统 Downloads，请选择接收目录".to_owned()
                    };
                    (defaults(), note, true, false)
                }
                Err(ConfigError::Corrupt(error)) => (
                    defaults(),
                    format!("配置损坏，原文件已保留；保存已禁用：{error}"),
                    false,
                    false,
                ),
                Err(error) => (
                    defaults(),
                    format!("配置读取失败，保存已禁用：{error}"),
                    false,
                    false,
                ),
            };

        let initial_password = if can_save_settings && settings.remote_auth.is_none() {
            let initialized = SecretPassword::generate().and_then(|password| {
                let verifier = RemoteVerifier::create(&password)?;
                DesktopConfig::save_remote_auth(&config_file, verifier.clone()).map_err(|_| {
                    crate::error::Error::Protocol("远程密码配置保存失败；认证保持禁用".into())
                })?;
                settings.remote_auth = Some(verifier);
                Ok(password)
            });
            match initialized {
                Ok(password) => {
                    config_note = "已生成远程访问密码；请显示并复制保存，仅保存派生密钥".into();
                    Some(password)
                }
                Err(error) => {
                    config_note = error.to_string();
                    None
                }
            }
        } else {
            None
        };
        Ok(Self {
            instance_lock,
            task_store,
            task_store_status,
            identity_id,
            identity,
            identity_status,
            config_file,
            settings,
            config_note,
            can_save_settings,
            has_saved_network_config,
            initial_password,
        })
    }
}

fn utf8_offset_from_utf16(content: &str, offset: usize) -> usize {
    let mut utf8_offset = 0;
    let mut utf16_count = 0;

    for ch in content.chars() {
        if utf16_count >= offset {
            break;
        }
        utf16_count += ch.len_utf16();
        utf8_offset += ch.len_utf8();
    }

    utf8_offset
}

fn utf16_offset_from_utf8(content: &str, offset: usize) -> usize {
    let mut utf16_offset = 0;
    let mut utf8_count = 0;

    for ch in content.chars() {
        if utf8_count >= offset {
            break;
        }
        utf8_count += ch.len_utf8();
        utf16_offset += ch.len_utf16();
    }

    utf16_offset
}

fn marked_selection_to_utf8(
    insertion_offset: usize,
    new_text: &str,
    selection_utf16: &Range<usize>,
) -> Range<usize> {
    insertion_offset + utf8_offset_from_utf16(new_text, selection_utf16.start)
        ..insertion_offset + utf8_offset_from_utf16(new_text, selection_utf16.end)
}

fn concurrency_value_replacement(
    current: &str,
    range: Range<usize>,
    new_text: &str,
) -> Option<(Range<usize>, String)> {
    if new_text.is_empty() {
        let remaining_len = current.len().saturating_sub(range.end - range.start);
        if remaining_len == 0 {
            return Some((0..current.len(), current.to_owned()));
        }
        return Some((range, String::new()));
    }

    new_text
        .chars()
        .find(|character| matches!(character, '1'..='3'))
        .map(|character| (0..current.len(), character.to_string()))
}

fn signal_server_spec(host: &str, port: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1_024. && unit + 1 < UNITS.len() {
        value /= 1_024.;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn mouse_index_for_layout(content: &str, layout_text: &str, index: usize) -> Option<usize> {
    if content != layout_text {
        return None;
    }

    let index = index.min(content.len());
    if content.is_char_boundary(index) {
        return Some(index);
    }

    Some(
        content
            .char_indices()
            .take_while(|(boundary, _)| *boundary < index)
            .map(|(boundary, _)| boundary)
            .last()
            .unwrap_or(0),
    )
}

fn password_display(content: &str, revealed: bool) -> String {
    if revealed {
        content.to_owned()
    } else {
        "*".repeat(content.len())
    }
}

struct TextField {
    focus_handle: FocusHandle,
    content: SharedString,
    placeholder: SharedString,
    concurrency_value_input: bool,
    secret: bool,
    revealed: bool,
    selected_range: Range<usize>,
    selection_reversed: bool,
    marked_range: Option<Range<usize>>,
    last_layout: Option<ShapedLine>,
    last_bounds: Option<Bounds<Pixels>>,
    is_selecting: bool,
}

impl TextField {
    fn new(cx: &mut Context<Self>, placeholder: &'static str) -> Self {
        Self {
            focus_handle: cx.focus_handle(),
            content: "".into(),
            placeholder: placeholder.into(),
            concurrency_value_input: false,
            secret: false,
            revealed: false,
            selected_range: 0..0,
            selection_reversed: false,
            marked_range: None,
            last_layout: None,
            last_bounds: None,
            is_selecting: false,
        }
    }

    fn new_password(cx: &mut Context<Self>, placeholder: &'static str) -> Self {
        let mut field = Self::new(cx, placeholder);
        field.secret = true;
        field
    }
    fn displayed_content(&self) -> SharedString {
        if self.secret {
            password_display(&self.content, self.revealed).into()
        } else {
            self.content.clone()
        }
    }
    fn new_concurrency_value(cx: &mut Context<Self>, value: u8) -> Self {
        let mut field = Self::new(cx, "1–3");
        field.content = value.to_string().into();
        field.selected_range = field.content.len()..field.content.len();
        field.concurrency_value_input = true;
        field
    }

    fn replacement_for_range(
        &self,
        range: Range<usize>,
        new_text: &str,
    ) -> Option<(Range<usize>, String)> {
        if self.secret
            && (!new_text.bytes().all(|b| b.is_ascii_alphanumeric())
                || self.content.len() - (range.end - range.start) + new_text.len() > 12)
        {
            return None;
        }
        if self.concurrency_value_input {
            concurrency_value_replacement(&self.content, range, new_text)
        } else {
            Some((range, new_text.to_owned()))
        }
    }

    fn left(&mut self, _: &Left, _: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.move_to(self.previous_boundary(self.cursor_offset()), cx);
        } else {
            self.move_to(self.selected_range.start, cx);
        }
    }

    fn right(&mut self, _: &Right, _: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.move_to(self.next_boundary(self.selected_range.end), cx);
        } else {
            self.move_to(self.selected_range.end, cx);
        }
    }

    fn select_left(&mut self, _: &SelectLeft, _: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.previous_boundary(self.cursor_offset()), cx);
    }

    fn select_right(&mut self, _: &SelectRight, _: &mut Window, cx: &mut Context<Self>) {
        self.select_to(self.next_boundary(self.cursor_offset()), cx);
    }

    fn select_all(&mut self, _: &SelectAll, _: &mut Window, cx: &mut Context<Self>) {
        self.move_to(0, cx);
        self.select_to(self.content.len(), cx);
    }

    fn home(&mut self, _: &Home, _: &mut Window, cx: &mut Context<Self>) {
        self.move_to(0, cx);
    }

    fn end(&mut self, _: &End, _: &mut Window, cx: &mut Context<Self>) {
        self.move_to(self.content.len(), cx);
    }

    fn backspace(&mut self, _: &Backspace, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.select_to(self.previous_boundary(self.cursor_offset()), cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn delete(&mut self, _: &Delete, window: &mut Window, cx: &mut Context<Self>) {
        if self.selected_range.is_empty() {
            self.select_to(self.next_boundary(self.cursor_offset()), cx);
        }
        self.replace_text_in_range(None, "", window, cx);
    }

    fn on_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.is_selecting = true;
        if let Some(index) = self.index_for_mouse_position(event.position) {
            if event.modifiers.shift {
                self.select_to(index, cx);
            } else {
                self.move_to(index, cx);
            }
        }
    }

    fn on_mouse_up(&mut self, _: &MouseUpEvent, _window: &mut Window, _: &mut Context<Self>) {
        self.is_selecting = false;
    }

    fn on_mouse_move(&mut self, event: &MouseMoveEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.is_selecting
            && let Some(index) = self.index_for_mouse_position(event.position)
        {
            self.select_to(index, cx);
        }
    }

    fn show_character_palette(
        &mut self,
        _: &ShowCharacterPalette,
        window: &mut Window,
        _: &mut Context<Self>,
    ) {
        window.show_character_palette();
    }

    fn paste(&mut self, _: &Paste, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
            self.replace_text_in_range(None, &text.replace('\n', " "), window, cx);
        }
    }

    fn copy(&mut self, _: &Copy, _: &mut Window, cx: &mut Context<Self>) {
        if !self.selected_range.is_empty() {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.content[self.selected_range.clone()].to_string(),
            ));
        }
    }

    fn cut(&mut self, _: &Cut, window: &mut Window, cx: &mut Context<Self>) {
        if !self.selected_range.is_empty() {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.content[self.selected_range.clone()].to_string(),
            ));
            self.replace_text_in_range(None, "", window, cx);
        }
    }

    fn move_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        self.selected_range = offset..offset;
        cx.notify();
    }

    fn cursor_offset(&self) -> usize {
        if self.selection_reversed {
            self.selected_range.start
        } else {
            self.selected_range.end
        }
    }

    fn index_for_mouse_position(&self, position: Point<Pixels>) -> Option<usize> {
        if self.content.is_empty() {
            return Some(0);
        }

        let (Some(bounds), Some(line)) = (self.last_bounds.as_ref(), self.last_layout.as_ref())
        else {
            return None;
        };
        if line.text != self.displayed_content() {
            return None;
        };
        if position.y < bounds.top() {
            return Some(0);
        }
        if position.y > bounds.bottom() {
            return Some(self.content.len());
        }
        mouse_index_for_layout(
            &self.displayed_content(),
            &line.text,
            line.closest_index_for_x(position.x - bounds.left()),
        )
    }

    fn select_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        if self.selection_reversed {
            self.selected_range.start = offset;
        } else {
            self.selected_range.end = offset;
        }
        if self.selected_range.end < self.selected_range.start {
            self.selection_reversed = !self.selection_reversed;
            self.selected_range = self.selected_range.end..self.selected_range.start;
        }
        cx.notify();
    }

    fn offset_from_utf16(&self, offset: usize) -> usize {
        utf8_offset_from_utf16(&self.content, offset)
    }

    fn offset_to_utf16(&self, offset: usize) -> usize {
        utf16_offset_from_utf8(&self.content, offset)
    }

    fn range_to_utf16(&self, range: &Range<usize>) -> Range<usize> {
        self.offset_to_utf16(range.start)..self.offset_to_utf16(range.end)
    }

    fn range_from_utf16(&self, range_utf16: &Range<usize>) -> Range<usize> {
        self.offset_from_utf16(range_utf16.start)..self.offset_from_utf16(range_utf16.end)
    }

    fn previous_boundary(&self, offset: usize) -> usize {
        self.content
            .grapheme_indices(true)
            .rev()
            .find_map(|(idx, _)| (idx < offset).then_some(idx))
            .unwrap_or(0)
    }

    fn next_boundary(&self, offset: usize) -> usize {
        self.content
            .grapheme_indices(true)
            .find_map(|(idx, _)| (idx > offset).then_some(idx))
            .unwrap_or(self.content.len())
    }
}

impl EntityInputHandler for TextField {
    fn text_for_range(
        &mut self,
        range_utf16: Range<usize>,
        actual_range: &mut Option<Range<usize>>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<String> {
        let range = self.range_from_utf16(&range_utf16);
        actual_range.replace(self.range_to_utf16(&range));
        Some(if self.secret {
            "*".repeat(range.len())
        } else {
            self.content[range].to_string()
        })
    }

    fn selected_text_range(
        &mut self,
        _ignore_disabled_input: bool,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<UTF16Selection> {
        Some(UTF16Selection {
            range: self.range_to_utf16(&self.selected_range),
            reversed: self.selection_reversed,
        })
    }

    fn marked_text_range(
        &self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Range<usize>> {
        self.marked_range
            .as_ref()
            .map(|range| self.range_to_utf16(range))
    }

    fn unmark_text(&mut self, _window: &mut Window, _cx: &mut Context<Self>) {
        self.marked_range = None;
    }

    fn replace_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range_utf16
            .as_ref()
            .map(|range_utf16| self.range_from_utf16(range_utf16))
            .or(self.marked_range.clone())
            .unwrap_or(self.selected_range.clone());
        let Some((range, new_text)) = self.replacement_for_range(range, new_text) else {
            return;
        };

        self.content =
            (self.content[0..range.start].to_owned() + &new_text + &self.content[range.end..])
                .into();
        self.selected_range = range.start + new_text.len()..range.start + new_text.len();
        self.marked_range.take();
        cx.notify();
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        new_selected_range_utf16: Option<Range<usize>>,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range_utf16
            .as_ref()
            .map(|range_utf16| self.range_from_utf16(range_utf16))
            .or(self.marked_range.clone())
            .unwrap_or(self.selected_range.clone());
        let Some((range, new_text)) = self.replacement_for_range(range, new_text) else {
            return;
        };

        self.content =
            (self.content[0..range.start].to_owned() + &new_text + &self.content[range.end..])
                .into();
        if !self.concurrency_value_input && !new_text.is_empty() {
            self.marked_range = Some(range.start..range.start + new_text.len());
        } else {
            self.marked_range = None;
        }
        self.selected_range = if self.concurrency_value_input {
            range.start + new_text.len()..range.start + new_text.len()
        } else {
            new_selected_range_utf16
                .as_ref()
                .map(|range_utf16| marked_selection_to_utf8(range.start, &new_text, range_utf16))
                .unwrap_or_else(|| range.start + new_text.len()..range.start + new_text.len())
        };
        cx.notify();
    }

    fn bounds_for_range(
        &mut self,
        range_utf16: Range<usize>,
        bounds: Bounds<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Bounds<Pixels>> {
        let last_layout = self.last_layout.as_ref()?;
        let range = self.range_from_utf16(&range_utf16);
        Some(Bounds::from_corners(
            point(
                bounds.left() + last_layout.x_for_index(range.start),
                bounds.top(),
            ),
            point(
                bounds.left() + last_layout.x_for_index(range.end),
                bounds.bottom(),
            ),
        ))
    }

    fn character_index_for_point(
        &mut self,
        point: gpui::Point<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<usize> {
        let line_point = self.last_bounds?.localize(&point)?;
        let last_layout = self.last_layout.as_ref()?;
        if last_layout.text != self.content {
            return None;
        }
        let utf8_index = last_layout.index_for_x(line_point.x)?;
        Some(self.offset_to_utf16(utf8_index))
    }
}

struct TextFieldElement {
    input: Entity<TextField>,
}

struct TextFieldPrepaintState {
    line: Option<ShapedLine>,
    cursor: Option<PaintQuad>,
    selection: Option<PaintQuad>,
}

impl IntoElement for TextFieldElement {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for TextFieldElement {
    type RequestLayoutState = ();
    type PrepaintState = TextFieldPrepaintState;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let mut style = Style::default();
        style.size.width = relative(1.).into();
        style.size.height = window.line_height().into();
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        let input = self.input.read(cx);
        let content = input.displayed_content();
        let selected_range = input.selected_range.clone();
        let cursor = input.cursor_offset();
        let style = window.text_style();

        let (display_text, text_color) = if content.is_empty() {
            (input.placeholder.clone(), hsla(0., 0., 0., 0.35))
        } else {
            (content, style.color)
        };

        let run = TextRun {
            len: display_text.len(),
            font: style.font(),
            color: text_color,
            background_color: None,
            underline: None,
            strikethrough: None,
        };
        let runs = if let Some(marked_range) = input.marked_range.as_ref() {
            vec![
                TextRun {
                    len: marked_range.start,
                    ..run.clone()
                },
                TextRun {
                    len: marked_range.end - marked_range.start,
                    underline: Some(UnderlineStyle {
                        color: Some(run.color),
                        thickness: px(1.0),
                        wavy: false,
                    }),
                    ..run.clone()
                },
                TextRun {
                    len: display_text.len() - marked_range.end,
                    ..run
                },
            ]
            .into_iter()
            .filter(|run| run.len > 0)
            .collect()
        } else {
            vec![run]
        };

        let font_size = style.font_size.to_pixels(window.rem_size());
        let line = window
            .text_system()
            .shape_line(display_text, font_size, &runs, None);

        let cursor_pos = line.x_for_index(cursor);
        let (selection, cursor) = if selected_range.is_empty() {
            (
                None,
                Some(fill(
                    Bounds::new(
                        point(bounds.left() + cursor_pos, bounds.top()),
                        size(px(2.), bounds.bottom() - bounds.top()),
                    ),
                    rgb(ui_theme::PRIMARY),
                )),
            )
        } else {
            (
                Some(fill(
                    Bounds::from_corners(
                        point(
                            bounds.left() + line.x_for_index(selected_range.start),
                            bounds.top(),
                        ),
                        point(
                            bounds.left() + line.x_for_index(selected_range.end),
                            bounds.bottom(),
                        ),
                    ),
                    rgba(0x3311a8ff),
                )),
                None,
            )
        };

        TextFieldPrepaintState {
            line: Some(line),
            cursor,
            selection,
        }
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        let focus_handle = self.input.read(cx).focus_handle.clone();
        window.handle_input(
            &focus_handle,
            ElementInputHandler::new(bounds, self.input.clone()),
            cx,
        );
        if let Some(selection) = prepaint.selection.take() {
            window.paint_quad(selection);
        }
        let line = prepaint.line.take().unwrap();
        line.paint(bounds.origin, window.line_height(), window, cx)
            .unwrap();

        if focus_handle.is_focused(window)
            && let Some(cursor) = prepaint.cursor.take()
        {
            window.paint_quad(cursor);
        }

        self.input.update(cx, |input, _cx| {
            input.last_layout = Some(line);
            input.last_bounds = Some(bounds);
        });
    }
}

impl Render for TextField {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let field = div()
            .flex()
            .w_full()
            .key_context("TextField")
            .track_focus(&self.focus_handle(cx))
            .cursor(CursorStyle::IBeam)
            .on_action(cx.listener(Self::backspace))
            .on_action(cx.listener(Self::delete))
            .on_action(cx.listener(Self::left))
            .on_action(cx.listener(Self::right))
            .on_action(cx.listener(Self::select_left))
            .on_action(cx.listener(Self::select_right))
            .on_action(cx.listener(Self::select_all))
            .on_action(cx.listener(Self::home))
            .on_action(cx.listener(Self::end))
            .on_action(cx.listener(Self::show_character_palette))
            .on_action(cx.listener(Self::paste))
            .on_action(cx.listener(Self::cut))
            .on_action(cx.listener(Self::copy))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_mouse_down))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_up_out(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_move(cx.listener(Self::on_mouse_move));
        if self.concurrency_value_input {
            field.line_height(px(18.)).text_size(px(12.)).child(
                div()
                    .h(px(24.))
                    .w_full()
                    .px(px(4.))
                    .bg(white())
                    .child(TextFieldElement { input: cx.entity() }),
            )
        } else {
            field.line_height(px(26.)).text_size(px(16.)).child(
                div()
                    .h(px(40.))
                    .w_full()
                    .p(px(7.))
                    .bg(white())
                    .child(TextFieldElement { input: cx.entity() }),
            )
        }
    }
}

impl Focusable for TextField {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

struct DesktopShell {
    peer_id: Entity<TextField>,
    peer_password: Entity<TextField>,
    local_password: Entity<TextField>,
    trusted_name: Entity<TextField>,
    editing_trusted: Option<NodeId>,
    local_short_id: Option<ShortId>,
    resolved_peer: Option<(String, NodeId)>,
    concurrency_input: Entity<TextField>,
    upload_limit_input: Entity<TextField>,
    download_limit_input: Entity<TextField>,
    receive_safety_input: Entity<TextField>,
    signal_host: Entity<TextField>,
    signal_port: Entity<TextField>,
    signal_tls_enabled: bool,
    signal_ca_file: Entity<TextField>,
    signal_server_name: Entity<TextField>,
    relay_server: Entity<TextField>,
    allowed_name: Entity<TextField>,
    allowed_target: Entity<TextField>,
    allowed_peers: Entity<TextField>,
    pending_tunnel_changes: std::collections::HashSet<String>,
    tunnel_name: Entity<TextField>,
    tunnel_peer: Entity<TextField>,
    tunnel_listen: Entity<TextField>,
    tunnel_target: Entity<TextField>,
    editing_allowed_id: Option<String>,
    editing_tunnel_id: Option<String>,
    selected_files: Vec<PathBuf>,
    native_dialogs: usize,
    selected_folder: Option<PathBuf>,
    settings: SettingsDraft,
    identity_id: Option<String>,
    identity: Option<Identity>,
    identity_status: SharedString,
    config_file: PathBuf,
    config_note: SharedString,
    can_save_settings: bool,
    is_saving_settings: bool,
    _instance_lock: InstanceLock,
    transfer_service: Option<transfer::TransferService>,
    network_session: Option<session::DesktopSessionHandle>,
    network_status: SharedString,
    signal_state: background::SignalState,
    background_files: (usize, usize, u64),
    network_path_status: SharedString,
    peer_path_status: HashMap<NodeId, (u64, String)>,
    connection_diagnostics: diagnostics::Diagnostics,
    show_diagnostics: bool,
    exporting_diagnostics: bool,
    peer_status: SharedString,
    network_epoch: u64,
    peer_generations: HashMap<NodeId, u64>,
    peer_states: HashMap<NodeId, network_state::PeerLifecycle>,
    tunnel_states: HashMap<String, session::TunnelRuntimeState>,
    tunnel_last_errors: HashMap<String, String>,
    task_rows: Vec<ui_model::ListRow>,
    task_snapshot: Vec<ui_model::TaskRow>,
    task_search: Entity<TextField>,
    task_filter: ui_model::TaskFilter,
    clearing_history: bool,
    outcome_alerts: notifications::OutcomeAlerts,
    native_alerts: notifications::NativeAlerts,
    notification_note: SharedString,
    expanded_groups: HashSet<task_model::TaskId>,
    selected_task: Option<task_model::TaskId>,
    detail_selection: Option<task_details::Selection>,
    task_details: Option<task_details::Detail>,
    detail_page: usize,
    revealing_task: bool,
    queue_status: SharedString,
    receive_space_status: SharedString,
    speed_views: ui_model::SpeedViews,
    speedtest_upload_result: Option<speed::SpeedSnapshot>,
    speed_peer: Option<NodeId>,
    speed_request_until: Option<Instant>,
    show_speed_test_panel: bool,
    show_speed_duration_menu: bool,
    show_settings: bool,
    show_settings_home: bool,
    pending_resumes: HashMap<NodeId, Vec<task_model::TaskId>>,
    applied_receive_root: Option<PathBuf>,
    task_scroll: gpui::UniformListScrollHandle,
    status: SharedString,
    focus_handle: FocusHandle,
}

impl Drop for DesktopShell {
    fn drop(&mut self) {
        if let Some(session) = self.network_session.as_ref() {
            session.shutdown();
        }
    }
}

impl DesktopShell {
    fn open_settings_home(&mut self, cx: &mut Context<Self>) {
        self.show_settings_home = true;
        cx.notify();
    }
    fn close_settings_home(&mut self, cx: &mut Context<Self>) {
        self.local_password.update(cx, |field, cx| {
            field.revealed = false;
            field.last_layout = None;
            cx.notify();
        });
        self.show_settings_home = false;
        cx.notify();
    }
    fn toggle_speed_test_panel(&mut self, cx: &mut Context<Self>) {
        self.show_speed_test_panel = !self.show_speed_test_panel;
        self.show_speed_duration_menu = false;
        cx.notify();
    }
    fn toggle_speed_duration_menu(&mut self, cx: &mut Context<Self>) {
        if self.is_saving_settings {
            return;
        }
        self.show_speed_duration_menu = !self.show_speed_duration_menu;
        cx.notify();
    }
    fn set_speedtest_duration(&mut self, seconds: u16, cx: &mut Context<Self>) {
        const OPTIONS: [u16; 5] = [30, 60, 120, 300, 600];
        if self.is_saving_settings || !OPTIONS.contains(&seconds) {
            return;
        }
        self.settings.speedtest_seconds = seconds;
        self.show_speed_duration_menu = false;
        cx.notify();
    }
    fn toggle_settings_home(&mut self, cx: &mut Context<Self>) {
        self.show_settings_home = !self.show_settings_home;
        cx.notify();
    }
    fn toggle_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.show_settings = !self.show_settings;
        let field = if self.show_settings {
            &self.signal_host
        } else {
            &self.peer_id
        };
        window.focus(&field.focus_handle(cx));
        cx.notify();
    }
    fn focus_field(&mut self, backwards: bool, window: &mut Window, cx: &mut Context<Self>) {
        let fields = if self.show_settings {
            vec![
                self.signal_host.clone(),
                self.signal_port.clone(),
                self.signal_ca_file.clone(),
                self.signal_server_name.clone(),
                self.relay_server.clone(),
                self.local_password.clone(),
                self.allowed_name.clone(),
                self.allowed_target.clone(),
                self.allowed_peers.clone(),
                self.tunnel_name.clone(),
                self.tunnel_peer.clone(),
                self.tunnel_listen.clone(),
                self.tunnel_target.clone(),
                self.peer_id.clone(),
            ]
        } else {
            vec![
                self.peer_id.clone(),
                self.peer_password.clone(),
                self.task_search.clone(),
            ]
        };
        let current = fields
            .iter()
            .position(|field| field.focus_handle(cx).is_focused(window));
        let next = match current {
            Some(i) if backwards => (i + fields.len() - 1) % fields.len(),
            Some(i) => (i + 1) % fields.len(),
            None => 0,
        };
        window.focus(&fields[next].focus_handle(cx));
    }
    fn select_task(&mut self, backwards: bool, cx: &mut Context<Self>) {
        let entries = self
            .task_rows
            .iter()
            .enumerate()
            .filter_map(|(i, r)| match r {
                ui_model::ListRow::Task(t) => Some((i, t.id.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();
        if entries.is_empty() {
            self.set_status("暂无可选文件任务；Ctrl/⌘+E 展开目录", cx);
            return;
        }
        let current = entries
            .iter()
            .position(|(_, id)| self.selected_task.as_ref() == Some(id));
        let next = match current {
            Some(i) if backwards => (i + entries.len() - 1) % entries.len(),
            Some(i) => (i + 1) % entries.len(),
            None => 0,
        };
        self.selected_task = Some(entries[next].1.clone());
        self.task_scroll
            .scroll_to_item(entries[next].0, gpui::ScrollStrategy::Center);
        cx.notify();
    }
    fn expand_groups(&mut self, cx: &mut Context<Self>) {
        let groups = self
            .task_rows
            .iter()
            .filter_map(|r| match r {
                ui_model::ListRow::Group(g) => Some(g.id.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        if groups.iter().all(|id| self.expanded_groups.contains(id)) {
            self.expanded_groups.clear();
        } else {
            self.expanded_groups.extend(groups);
        }
        self.refresh_task_rows(cx);
    }
    fn observe_tasks(&mut self, cx: &mut Context<Self>) {
        let Some(service) = self.transfer_service.clone() else {
            self.queue_status = "任务存储不可用".into();
            return;
        };
        let background = cx.background_executor().clone();
        cx.spawn(async move |shell, cx| {
            loop {
                let service = service.clone();
                let result = background.spawn(async move { service.ui_snapshot() }).await;
                if shell
                    .update(cx, |shell, cx| {
                        match result {
                            Ok(snapshot) => {
                                if snapshot.detail_selection == shell.detail_selection
                                    && shell.detail_selection.is_some()
                                {
                                    if let Some(detail) = snapshot.detail {
                                        if Some(&detail.selection)
                                            == shell.detail_selection.as_ref()
                                        {
                                            shell.task_details = Some(detail);
                                        }
                                    } else {
                                        shell.close_task_details(cx);
                                        shell
                                            .set_status("所选任务或目录组已不可用，详情已关闭", cx);
                                    }
                                }
                                shell.receive_space_status = format!(
                                    "接收预算已预约 {:.1} MiB · {} 个文件系统",
                                    snapshot.space.reserved as f64 / (1024. * 1024.),
                                    snapshot.space.filesystems
                                )
                                .into();
                                shell.queue_status = format!(
                                    "排队 {} · 活动文件 {}/{}{}",
                                    snapshot.queue.pending,
                                    snapshot.queue.active_files,
                                    snapshot.queue.limit,
                                    if snapshot.queue.converging {
                                        " · 正在收敛到新并发数"
                                    } else {
                                        ""
                                    }
                                )
                                .into();
                                shell.background_files = (
                                    snapshot
                                        .tasks
                                        .iter()
                                        .filter(|task| {
                                            task.state == task_model::TaskState::Transferring
                                        })
                                        .count(),
                                    snapshot
                                        .tasks
                                        .iter()
                                        .filter(|task| task.state == task_model::TaskState::Queued)
                                        .count(),
                                    snapshot
                                        .tasks
                                        .iter()
                                        .filter(|task| {
                                            task.state == task_model::TaskState::Transferring
                                        })
                                        .map(|task| task.rate.max(0.) as u64)
                                        .sum(),
                                );
                                if let Some(notice) = shell.outcome_alerts.observe(
                                    &snapshot.tasks,
                                    shell.settings.notifications,
                                    Instant::now(),
                                ) {
                                    shell.native_alerts.show(notice);
                                }
                                shell.task_snapshot = snapshot.tasks.clone();
                                shell.refresh_task_rows(cx);
                                for event in shell.native_alerts.poll() {
                                    match event {
                                        notifications::AlertEvent::Open(id) => {
                                            shell.focus_notified_task(id, cx);
                                            cx.defer(background::reopen);
                                        }
                                        notifications::AlertEvent::Ready => {
                                            shell.notification_note = "系统通知已就绪".into()
                                        }
                                        notifications::AlertEvent::Unavailable => {
                                            shell.notification_note =
                                                "系统通知暂不可用；请检查系统权限，传输继续运行"
                                                    .into()
                                        }
                                    }
                                }
                                shell.speed_views.update(snapshot.speeds, Instant::now());
                                if shell
                                    .speed_request_until
                                    .is_some_and(|until| Instant::now() >= until)
                                    || shell
                                        .speed_views
                                        .0
                                        .values()
                                        .any(|v| v.snapshot.status == speed::SpeedStatus::Running)
                                {
                                    shell.speed_request_until = None;
                                }
                            }
                            Err(e) => shell.queue_status = format!("无法读取任务：{e}").into(),
                        }
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
                background.timer(Duration::from_millis(250)).await;
            }
        })
        .detach();
    }
    fn selected_peer(&self, cx: &Context<Self>) -> Option<NodeId> {
        let text = self.peer_id.read(cx).content.trim();
        NodeId::from_hex(text).ok().or_else(|| {
            self.resolved_peer
                .as_ref()
                .filter(|(query, _)| query == text)
                .map(|(_, peer)| *peer)
        })
    }
    fn authenticated_peer(&mut self, cx: &mut Context<Self>) -> Option<NodeId> {
        let result = self.selected_peer(cx);
        let Some(peer) = result else {
            self.set_status("请先输入对端设备 ID 和密码并连接", cx);
            return None;
        };
        if !self
            .peer_states
            .get(&peer)
            .is_some_and(network_state::PeerLifecycle::outbound_authorized)
        {
            self.set_status("请先连接并等待远程访问授权完成", cx);
            return None;
        }
        if self.transfer_service.is_none() {
            self.set_status("任务存储不可用", cx);
            return None;
        }
        Some(peer)
    }
    fn start_speed_ui(&mut self, cx: &mut Context<Self>) {
        if self.speed_request_until.is_some()
            || self
                .speed_views
                .0
                .values()
                .any(|v| v.snapshot.status == speed::SpeedStatus::Running)
        {
            self.set_status("测速正在进行，请先取消或等待完成", cx);
            return;
        }
        let Some(peer) = self.authenticated_peer(cx) else {
            return;
        };
        let direction = self.settings.speedtest_direction;
        let seconds = self.settings.speedtest_seconds;
        let result = self
            .network_session
            .as_ref()
            .ok_or("网络会话已关闭".to_owned())
            .and_then(|s| s.start_speed(peer, direction, seconds));
        match result {
            Ok(()) => {
                self.speed_peer = Some(peer);
                self.speedtest_upload_result = None;
                self.speed_request_until = Some(Instant::now() + Duration::from_secs(6));
                self.set_status(
                    if direction == SpeedtestDirection::Both {
                        format!("正在请求双向测速；先上传后下载，每个方向 {seconds} 秒")
                    } else {
                        "正在请求测速；有文件活动时需先暂停，不会自动暂停任务".to_owned()
                    },
                    cx,
                );
            }
            Err(e) => self.set_status(e, cx),
        }
    }
    fn displayed_speed(&self) -> Option<(NodeId, &ui_model::SpeedView)> {
        self.speed_views
            .0
            .iter()
            .filter(|(_, v)| v.snapshot.status == speed::SpeedStatus::Running)
            .min_by_key(|(peer, _)| peer.to_hex())
            .map(|(peer, v)| (*peer, v))
            .or_else(|| {
                self.speed_peer
                    .and_then(|p| self.speed_views.0.get(&p).map(|v| (p, v)))
            })
            .or_else(|| {
                self.speed_views
                    .0
                    .iter()
                    .min_by_key(|(peer, _)| peer.to_hex())
                    .map(|(p, v)| (*p, v))
            })
    }
    fn cancel_speed_ui(&mut self, cx: &mut Context<Self>) {
        let Some((peer, view)) = self
            .displayed_speed()
            .filter(|(_, v)| v.snapshot.status == speed::SpeedStatus::Running)
        else {
            self.set_status("当前没有已获得授权的测速", cx);
            return;
        };
        let id = view.snapshot.test_id.clone();
        let result = self
            .network_session
            .as_ref()
            .ok_or("网络会话已关闭".to_owned())
            .and_then(|s| s.cancel_speed(peer, id));
        match result {
            Ok(()) => self.set_status("正在取消测速，等待对端确认与清理", cx),
            Err(e) => self.set_status(e, cx),
        }
    }
    fn task_action(&mut self, id: task_model::TaskId, resume: bool, cx: &mut Context<Self>) {
        let row = self.task_rows.iter().find_map(|r| match r {
            ui_model::ListRow::Task(t) if t.id == id => Some(t.clone()),
            _ => None,
        });
        let Some(row) = row else {
            self.set_status("请展开目录并选择要操作的任务", cx);
            return;
        };
        if (resume && !row.can_continue()) || (!resume && !row.can_pause()) {
            self.set_status("该任务当前不能执行此操作", cx);
            return;
        }
        let result = self
            .network_session
            .as_ref()
            .ok_or("请先保存信令配置，启动网络会话".to_owned())
            .and_then(|s| {
                if resume {
                    if !self
                        .peer_states
                        .get(&row.peer)
                        .is_some_and(network_state::PeerLifecycle::outbound_authorized)
                    {
                        let password =
                            SecretPassword::new(self.peer_password.read(cx).content.to_string())
                                .map_err(|e| e.to_string())?;
                        s.connect_peer_with_password(row.peer, password)?;
                        let pending = self.pending_resumes.entry(row.peer).or_default();
                        if !pending.contains(&row.id) {
                            pending.push(row.id);
                        }
                        Ok(())
                    } else {
                        s.resume_task(row.peer, row.id)
                    }
                } else {
                    s.pause_task(row.id)
                }
            });
        match result {
            Ok(()) => self.set_status(
                if resume {
                    "已请求继续；任务使用原先绑定的对端"
                } else {
                    "正在暂停，等待持久化和双方确认"
                },
                cx,
            ),
            Err(e) => self.set_status(e, cx),
        }
    }
    fn selected_action(&mut self, resume: bool, cx: &mut Context<Self>) {
        if let Some(id) = self.selected_task.clone() {
            self.task_action(id, resume, cx);
        } else {
            self.set_status("先点击任务行选择任务", cx);
        }
    }
    fn remove_task_history(&mut self, id: task_model::TaskId, cx: &mut Context<Self>) {
        let completed = self.task_rows.iter().any(|row| {
            matches!(row, ui_model::ListRow::Task(task) if task.id == id && task.can_remove_history())
        });
        if !completed {
            self.set_status("只能移除已完成任务的历史记录", cx);
            return;
        }
        let Some(service) = self.transfer_service.clone() else {
            self.set_status("任务存储不可用", cx);
            return;
        };
        let background = cx.background_executor().clone();
        let removed_id = id.clone();
        cx.spawn(async move |shell, cx| {
            let result = background
                .spawn(async move { service.remove_completed_task(&id) })
                .await;
            let _ = shell.update(cx, move |shell, cx| match result {
                Ok(()) => {
                    if shell.selected_task.as_ref() == Some(&removed_id) {
                        shell.selected_task = None;
                    }
                    shell.set_status("已移除完成任务记录；传输文件保留在原位置", cx);
                }
                Err(error) => shell.set_status(format!("移除任务历史记录失败：{error}"), cx),
            });
        })
        .detach();
    }
    fn refresh_task_rows(&mut self, cx: &mut Context<Self>) {
        let snapshot = ui_model::Snapshot {
            space: Default::default(),
            detail_selection: None,
            detail: None,
            tasks: self.task_snapshot.clone(),
            queue: queue::TaskQueue::default().metrics(),
            speeds: HashMap::new(),
        };
        self.task_rows = snapshot.filtered_list(
            &self.expanded_groups,
            &self.task_filter,
            &self.settings.trusted_devices,
        );
        if self.selected_task.as_ref().is_some_and(|id| {
            !self
                .task_rows
                .iter()
                .any(|r| matches!(r, ui_model::ListRow::Task(t) if &t.id == id))
        }) {
            self.selected_task = None;
        }
        cx.notify();
    }
    fn reset_task_filters(&mut self, cx: &mut Context<Self>) {
        self.task_filter = Default::default();
        Self::set_text_field(&self.task_search, "", cx);
        self.refresh_task_rows(cx);
    }
    fn task_filter_toolbar(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        use task_model::{TaskDirection, TaskState};
        let directions = [
            None,
            Some(TaskDirection::Send),
            Some(TaskDirection::Receive),
        ];
        let states = [
            None,
            Some(TaskState::Completed),
            Some(TaskState::Failed),
            Some(TaskState::Interrupted),
            Some(TaskState::Paused),
            Some(TaskState::Transferring),
            Some(TaskState::Queued),
            Some(TaskState::Connecting),
            Some(TaskState::Negotiating),
            Some(TaskState::Pausing),
            Some(TaskState::Finalizing),
            Some(TaskState::Scanning),
        ];
        let direction = match self.task_filter.direction {
            None => "全部方向",
            Some(TaskDirection::Send) => "发送",
            Some(TaskDirection::Receive) => "接收",
        };
        let state = self
            .task_filter
            .state
            .map_or("全部状态", ui_model::state_label);
        let peer = self.task_filter.peer.map_or("全部设备".to_owned(), |peer| {
            format!("设备 {}", peer.short())
        });
        div()
            .flex()
            .items_center()
            .gap_2()
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .child(Self::compact_text_field_frame(
                        &self.task_search,
                        window,
                        cx,
                    )),
            )
            .child(
                ui_components::compact_secondary_button(peer, true).on_mouse_up(
                    MouseButton::Left,
                    cx.listener(|shell, _, _, cx| {
                        let mut peers: Vec<_> =
                            shell.task_snapshot.iter().map(|t| t.peer).collect();
                        peers.sort_by_key(|p| p.to_hex());
                        peers.dedup();
                        let next = shell
                            .task_filter
                            .peer
                            .and_then(|p| peers.iter().position(|v| *v == p))
                            .map_or(0, |i| i + 1);
                        shell.task_filter.peer = peers.get(next).copied();
                        shell.refresh_task_rows(cx);
                    }),
                ),
            )
            .child(
                ui_components::compact_secondary_button(direction, true).on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |shell, _, _, cx| {
                        let next = directions
                            .iter()
                            .position(|d| *d == shell.task_filter.direction)
                            .unwrap_or(0)
                            + 1;
                        shell.task_filter.direction = directions[next % directions.len()];
                        shell.refresh_task_rows(cx);
                    }),
                ),
            )
            .child(
                ui_components::compact_secondary_button(state, true).on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |shell, _, _, cx| {
                        let next = states
                            .iter()
                            .position(|s| *s == shell.task_filter.state)
                            .unwrap_or(0)
                            + 1;
                        shell.task_filter.state = states[next % states.len()];
                        shell.refresh_task_rows(cx);
                    }),
                ),
            )
            .child(
                ui_components::compact_secondary_button("重置", self.task_filter.active())
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|shell, _, _, cx| shell.reset_task_filters(cx)),
                    ),
            )
            .child(
                ui_components::compact_secondary_button(
                    "清理完成历史",
                    !self.clearing_history && self.transfer_service.is_some(),
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(Self::clear_completed_history),
                ),
            )
    }
    fn clear_completed_history(
        &mut self,
        _: &MouseUpEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.clearing_history {
            return;
        }
        let ids: std::collections::BTreeSet<_> = self
            .task_snapshot
            .iter()
            .filter(|t| {
                t.state == task_model::TaskState::Completed
                    && self.task_filter.matches(t, &self.settings.trusted_devices)
            })
            .map(|t| t.id.clone())
            .collect();
        if ids.is_empty() {
            self.set_status("当前筛选内没有已完成记录", cx);
            return;
        }
        let Some(service) = self.transfer_service.clone() else {
            return;
        };
        let detail = format!(
            "清理当前筛选内最多 {} 条已完成记录。传输文件保留；未完成、仍活动或未被完整选中的目录组保留。历史记录清理后无法恢复。",
            ids.len()
        );
        let confirmation = window.prompt(
            PromptLevel::Warning,
            "清理已完成历史？",
            Some(&detail),
            &[PromptButton::cancel("取消"), PromptButton::ok("清理记录")],
            cx,
        );
        self.clearing_history = true;
        cx.notify();
        let executor = cx.background_executor().clone();
        cx.spawn(async move |shell, cx| {
            let result = if confirmation.await.ok() == Some(1) {
                Some(
                    executor
                        .spawn(async move { service.remove_completed_history(ids) })
                        .await,
                )
            } else {
                None
            };
            let _ = shell.update(cx, move |shell, cx| {
                shell.clearing_history = false;
                match result {
                    Some(Ok(removed)) => {
                        if shell
                            .selected_task
                            .as_ref()
                            .is_some_and(|id| removed.contains(id))
                        {
                            shell.selected_task = None;
                        }
                        shell.set_status(
                            format!(
                                "已清理 {} 条完成历史；传输文件保留，未满足条件的目录组保留",
                                removed.len()
                            ),
                            cx,
                        );
                    }
                    Some(Err(error)) => shell.set_status(format!("历史清理未完成：{error}"), cx),
                    None => cx.notify(),
                }
            });
        })
        .detach();
    }
    fn confirm_delete_received_file(
        &mut self,
        id: task_model::TaskId,
        name: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.native_dialogs > 0 {
            return;
        }
        let eligible = self.task_rows.iter().any(|row| {
            matches!(row, ui_model::ListRow::Task(task) if task.id == id && task.can_delete_file())
        });
        if !eligible {
            self.set_status("仅已完成的接收文件可以删除", cx);
            return;
        }
        let Some(service) = self.transfer_service.clone() else {
            self.set_status("任务存储不可用", cx);
            return;
        };
        let detail = format!("将从接收目录永久删除“{name}”，并移除对应任务记录。此操作无法撤销。");
        self.native_dialogs += 1;
        cx.notify();
        let confirmation = window.prompt(
            PromptLevel::Warning,
            "确定删除已接收文件？",
            Some(&detail),
            &[PromptButton::cancel("取消"), PromptButton::ok("删除文件")],
            cx,
        );
        let background = cx.background_executor().clone();
        cx.spawn(async move |shell, cx| {
            if confirmation.await.ok() != Some(1) {
                let _ = shell.update(cx, |shell, cx| {
                    shell.native_dialogs = shell.native_dialogs.saturating_sub(1);
                    cx.notify();
                });
                return;
            }
            let delete_id = id.clone();
            let result = background
                .spawn(async move { service.delete_completed_receive_file(&delete_id) })
                .await;
            let _ = shell.update(cx, move |shell, cx| {
                shell.native_dialogs = shell.native_dialogs.saturating_sub(1);
                match result {
                    Ok(()) => {
                        if shell.selected_task.as_ref() == Some(&id) {
                            shell.selected_task = None;
                        }
                        shell.set_status("已删除接收文件，并移除完成记录", cx);
                    }
                    Err(error) => shell.set_status(format!("删除接收文件失败：{error}"), cx),
                }
            });
        })
        .detach();
    }
    fn show_task_details(&mut self, selection: task_details::Selection, cx: &mut Context<Self>) {
        if self.detail_selection.as_ref() != Some(&selection) {
            self.task_details = None;
            self.detail_page = 0;
        }
        self.detail_selection = Some(selection.clone());
        if let Some(service) = &self.transfer_service {
            service.select_detail(Some(selection));
        }
        cx.notify();
    }
    fn close_task_details(&mut self, cx: &mut Context<Self>) {
        self.detail_selection = None;
        self.task_details = None;
        self.detail_page = 0;
        if let Some(service) = &self.transfer_service {
            service.select_detail(None);
        }
        cx.notify();
    }
    fn reveal_task_details(&mut self, cx: &mut Context<Self>) {
        if self.revealing_task || self.native_dialogs > 0 || self.clearing_history {
            return;
        }
        let Some(selection) = self.detail_selection.clone() else {
            return;
        };
        let Some(service) = self.transfer_service.clone() else {
            return;
        };
        let requested = selection.clone();
        let executor = cx.background_executor().clone();
        self.revealing_task = true;
        cx.notify();
        cx.spawn(async move |shell, cx| {
            let result = executor
                .spawn(async move { service.reveal_task(&requested) })
                .await;
            let _ = shell.update(cx, |shell, cx| {
                shell.revealing_task = false;
                if shell.detail_selection.as_ref() == Some(&selection)
                    && shell.native_dialogs == 0
                    && !shell.clearing_history
                    && !shell.show_settings_home
                {
                    match result {
                        Ok(path) => {
                            cx.reveal_path(&path);
                            shell.set_status("已请求在本机文件管理器定位任务路径", cx);
                        }
                        Err(error) => shell.set_status(format!("本机路径暂无法定位：{error}"), cx),
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn detail_field(label: &str, value: String) -> gpui::Div {
        div()
            .flex()
            .items_start()
            .gap_3()
            .child(
                div()
                    .w(px(132.))
                    .flex_shrink_0()
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child(label.to_owned()),
            )
            .child(div().flex_1().min_w_0().text_sm().child(value))
    }
    fn task_details_card(&self, cx: &mut Context<Self>) -> gpui::Div {
        let mut card = ui_components::card().child(
            div()
                .flex()
                .justify_between()
                .items_center()
                .child(ui_components::section_header(
                    "ⓘ",
                    "任务详情",
                    "选择任务或目录组，查看统计与本机位置",
                ))
                .child(
                    ui_components::compact_secondary_button("关闭详情", true).on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|shell, _, _, cx| shell.close_task_details(cx)),
                    ),
                ),
        );
        let Some(detail) = &self.task_details else {
            return card.child("正在读取任务详情…");
        };
        if let Some(parent) = &detail.parent_group {
            let parent = parent.clone();
            card = card.child(
                ui_components::compact_secondary_button("返回目录组", true).on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |shell, _, _, cx| {
                        shell.show_task_details(task_details::Selection::Group(parent.clone()), cx)
                    }),
                ),
            );
        }
        let group = matches!(detail.selection, task_details::Selection::Group(_));
        let direction = if detail.direction == task_model::TaskDirection::Send {
            "发送"
        } else {
            "接收"
        };
        let elapsed = detail
            .wall_seconds
            .map_or_else(|| "未知（系统时间不可用）".into(), task_details::duration);
        let activity = if detail.run.covered == 0 {
            "本次运行暂无活动统计".to_owned()
        } else {
            format!(
                "{} · 已记录 {}/{} 项{}",
                task_details::duration(detail.run.seconds),
                detail.run.covered,
                detail.members.len(),
                if group { "（子项累计）" } else { "" }
            )
        };
        let attempts = if detail.run.covered == 0 {
            "本次运行暂无尝试统计".to_owned()
        } else {
            format!(
                "已启动 {} 次 · 重新尝试 {} 次 · 自动尝试 {} 次",
                detail.run.attempts, detail.run.retries, detail.run.automatic
            )
        };
        let path = detail.local_path.to_string_lossy().into_owned();
        let copy_path = path.clone();
        card = card.child(div().text_xs().text_color(rgb(ui_theme::TEXT_SECONDARY)).child(detail.scope_label))
            .child(Self::detail_field("任务名称", detail.name.clone()))
            .child(Self::detail_field("设备 / 方向 / 状态", format!("{} · {direction} · {}", detail.peer.short(), detail.state)))
            .child(Self::detail_field("已确认 / 总大小", format!("{} / {}（{} / {} 字节）", format_bytes(detail.confirmed), format_bytes(detail.total), detail.confirmed, detail.total)))
            .child(Self::detail_field("当前文件速度", if detail.rate > 0. { format!("{:.2} MiB/s", detail.rate / 1_048_576.) } else { "未知 / 无活动文件速度".into() }))
            .child(Self::detail_field("数据预计剩余", detail.eta.map_or_else(|| "未知".into(), task_details::duration)))
            .child(Self::detail_field("创建至今或结果", format!("{elapsed}（含等待和暂停）")))
            .child(Self::detail_field("本次活动用时", activity))
            .child(Self::detail_field("本次尝试统计", attempts))
            .child(Self::detail_field("本机绑定位置", path))
            .child(div().flex().gap_2()
                .child(ui_components::compact_secondary_button("复制本机路径", true).on_mouse_up(MouseButton::Left, cx.listener(move |shell, _, _, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string(copy_path.clone())); shell.set_status("已复制任务绑定的本机路径", cx);
                })))
                .child(ui_components::compact_secondary_button(detail.reveal_label, !self.revealing_task && self.native_dialogs == 0 && !self.clearing_history)
                    .on_mouse_up(MouseButton::Left, cx.listener(|shell, _, _, cx| shell.reveal_task_details(cx)))))
            .child(div().text_xs().text_color(rgb(ui_theme::TEXT_MUTED)).child("预计时间按当前文件速度估算，不含排队等待和验证收尾；等待、暂停、失败或缺少速度时显示未知。本次活动时间包含验证及收尾，暂停和排队时不累计。"));
        for (message, count, retryable) in &detail.errors {
            card = card.child(
                div()
                    .text_sm()
                    .text_color(rgb(ui_theme::DANGER))
                    .child(format!(
                        "{message} · {count} 项{}",
                        if *retryable {
                            " · 可手动继续"
                        } else {
                            ""
                        }
                    )),
            );
        }
        if group {
            let counts = detail.counts;
            card = card.child(Self::detail_field("全部保留子项", format!("文件 {} · 目录 {} · 完成 {} · 失败 {} · 暂停 {} · 中断 {} · 自动等待 {} · 排队 {} · 活动 {}", counts.files, counts.directories, counts.completed, counts.failed, counts.paused, counts.interrupted, counts.waiting, counts.queued, counts.active)));
            let pages = detail.members.len().div_ceil(10).max(1);
            let page = self.detail_page.min(pages - 1);
            for member in detail.members.iter().skip(page * 10).take(10) {
                let id = member.id.clone();
                card = card.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(div().flex_1().min_w_0().text_xs().child(format!(
                                "{} · {} · {} / {} · {}{}",
                                if member.directory { "目录" } else { "文件" },
                                member.name,
                                format_bytes(member.confirmed),
                                format_bytes(member.total),
                                member.state,
                                member
                                    .diagnostic
                                    .map_or(String::new(), |message| format!(" · {message}"))
                            )))
                        .child(
                            ui_components::compact_secondary_button("查看", true).on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |shell, _, _, cx| {
                                    shell.show_task_details(
                                        task_details::Selection::Task(id.clone()),
                                        cx,
                                    )
                                }),
                            ),
                        ),
                );
            }
            card = card.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        ui_components::compact_secondary_button("上一页", page > 0).on_mouse_up(
                            MouseButton::Left,
                            cx.listener(|shell, _, _, cx| {
                                shell.detail_page = shell.detail_page.saturating_sub(1);
                                cx.notify();
                            }),
                        ),
                    )
                    .child(format!(
                        "子项 {}/{} 页 · 共 {} 项",
                        page + 1,
                        pages,
                        detail.members.len()
                    ))
                    .child(
                        ui_components::compact_secondary_button("下一页", page + 1 < pages)
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |shell, _, _, cx| {
                                    shell.detail_page = (shell.detail_page + 1).min(pages - 1);
                                    cx.notify();
                                }),
                            ),
                    ),
            );
        }
        card
    }
    fn task_row(&mut self, index: usize, cx: &mut Context<Self>) -> gpui::Div {
        let row = self.task_rows[index].clone();
        match row {
            ui_model::ListRow::Group(group) => {
                let expanded =
                    self.task_filter.active() || self.expanded_groups.contains(&group.id);
                let id = group.id.clone();
                let detail_id = id.clone();
                div()
                    .w_full()
                    .h(px(64.))
                    .px(px(12.))
                    .flex()
                    .items_center()
                    .gap_3()
                    .border_b_1()
                    .border_color(rgb(ui_theme::BORDER))
                    .bg(rgb(ui_theme::PRIMARY_SOFT))
                    .cursor(CursorStyle::PointingHand)
                    .child(
                        div()
                            .w(px(32.))
                            .h(px(32.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded_md()
                            .bg(white())
                            .text_color(rgb(ui_theme::PRIMARY))
                            .child(if expanded { "▾" } else { "▸" }),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(gpui::FontWeight::MEDIUM)
                                    .truncate()
                                    .child(group.name.clone()),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                    .truncate()
                                    .child(group.label()),
                            ),
                    )
                    .child(
                        ui_components::compact_secondary_button("详情", true).on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |shell, _, _, cx| {
                                cx.stop_propagation();
                                shell.show_task_details(
                                    task_details::Selection::Group(detail_id.clone()),
                                    cx,
                                );
                            }),
                        ),
                    )
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                            if !shell.expanded_groups.remove(&id) {
                                shell.expanded_groups.insert(id.clone());
                            }
                            shell.refresh_task_rows(cx);
                        }),
                    )
            }
            ui_model::ListRow::Task(task) => {
                let id = task.id.clone();
                let select = id.clone();
                let pause = id.clone();
                let resume = id.clone();
                let remove = id.clone();
                let delete = id.clone();
                let delete_name = task.name.clone();
                let can_pause = task.can_pause();
                let can_continue = task.can_continue();
                let can_remove = task.can_remove_history();
                let can_delete_file = task.can_delete_file();
                let is_send = task.direction == task_model::TaskDirection::Send;
                let direction = if is_send { "发送" } else { "接收" };
                let (status_color, status_background) = match task.state {
                    task_model::TaskState::Scanning | task_model::TaskState::Queued => {
                        (ui_theme::TEXT_SECONDARY, ui_theme::SURFACE_SUBTLE)
                    }
                    task_model::TaskState::Connecting
                    | task_model::TaskState::Negotiating
                    | task_model::TaskState::Transferring
                    | task_model::TaskState::Finalizing => {
                        (ui_theme::PRIMARY, ui_theme::PRIMARY_SOFT)
                    }
                    task_model::TaskState::Pausing | task_model::TaskState::Paused => {
                        (ui_theme::WARNING, ui_theme::WARNING_SOFT)
                    }
                    task_model::TaskState::Interrupted | task_model::TaskState::Failed => {
                        (ui_theme::DANGER, ui_theme::DANGER_SOFT)
                    }
                    task_model::TaskState::Completed => (ui_theme::SUCCESS, ui_theme::SUCCESS_SOFT),
                };
                let progress = task.percent();
                let confirmed = format_bytes(task.confirmed);
                let total = format_bytes(task.total);
                let rate = if task.rate > 0. {
                    format!("{:.2} MiB/s", task.rate / 1_048_576.)
                } else {
                    "—".to_owned()
                };
                let diagnostic = task.diagnostic.map(|detail| format!(" · {detail}"));
                let metadata = format!(
                    "{} · {confirmed} / {total} · {rate}{}",
                    task.state_label(),
                    diagnostic.unwrap_or_default()
                );
                let icon = if is_send { "↑" } else { "↓" };
                let detail_id = id.clone();
                let mut actions = div()
                    .w(px(104.))
                    .flex()
                    .items_center()
                    .justify_end()
                    .gap_1()
                    .child(
                        ui_components::compact_secondary_button("详情", true).on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |shell, _, _, cx| {
                                cx.stop_propagation();
                                shell.show_task_details(
                                    task_details::Selection::Task(detail_id.clone()),
                                    cx,
                                );
                            }),
                        ),
                    );
                if can_pause {
                    actions = actions.child(
                        ui_components::task_icon_button(
                            ui_components::TaskActionIcon::Pause,
                            false,
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                shell.task_action(pause.clone(), false, cx);
                            }),
                        ),
                    );
                }
                if can_continue {
                    actions = actions.child(
                        ui_components::task_icon_button(
                            ui_components::TaskActionIcon::Resume,
                            false,
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                shell.task_action(resume.clone(), true, cx);
                            }),
                        ),
                    );
                }
                if can_remove {
                    actions = actions.child(
                        ui_components::task_icon_button(
                            ui_components::TaskActionIcon::Remove,
                            false,
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                shell.remove_task_history(remove.clone(), cx);
                            }),
                        ),
                    );
                }
                if can_delete_file {
                    actions = actions.child(
                        ui_components::task_icon_button(
                            ui_components::TaskActionIcon::Delete,
                            true,
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |shell, _: &MouseUpEvent, window, cx| {
                                shell.confirm_delete_received_file(
                                    delete.clone(),
                                    delete_name.clone(),
                                    window,
                                    cx,
                                );
                            }),
                        ),
                    );
                }

                div()
                    .w_full()
                    .h(px(64.))
                    .px(px(12.))
                    .flex()
                    .items_center()
                    .gap_3()
                    .border_b_1()
                    .border_color(rgb(ui_theme::BORDER))
                    .bg(if self.selected_task.as_ref() == Some(&id) {
                        rgb(ui_theme::PRIMARY_SOFT)
                    } else {
                        rgb(ui_theme::SURFACE)
                    })
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                            shell.selected_task = Some(select.clone());
                            cx.notify();
                        }),
                    )
                    .child(
                        div()
                            .w(px(36.))
                            .h(px(36.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded_md()
                            .bg(rgb(status_background))
                            .text_color(rgb(status_color))
                            .text_size(px(18.))
                            .font_weight(gpui::FontWeight::BOLD)
                            .child(icon),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap(px(2.))
                            .line_height(px(14.))
                            .child(
                                div()
                                    .h(px(18.))
                                    .line_height(px(18.))
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w_0()
                                            .truncate()
                                            .text_sm()
                                            .font_weight(gpui::FontWeight::MEDIUM)
                                            .child(task.name.clone()),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                            .child(direction),
                                    )
                                    .child(
                                        div()
                                            .px(px(6.))
                                            .py(px(0.))
                                            .rounded_md()
                                            .bg(rgb(status_background))
                                            .text_xs()
                                            .text_color(rgb(status_color))
                                            .child(task.state_label()),
                                    ),
                            )
                            .child(
                                div()
                                    .h(px(12.))
                                    .line_height(px(12.))
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(ui_components::compact_progress_bar(progress))
                                    .child(
                                        div()
                                            .w(px(48.))
                                            .text_xs()
                                            .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                            .child(format!("{progress:.1}%")),
                                    ),
                            )
                            .child(
                                div()
                                    .h(px(14.))
                                    .line_height(px(14.))
                                    .text_xs()
                                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                    .truncate()
                                    .child(metadata),
                            ),
                    )
                    .child(actions)
            }
        }
    }
    fn set_status(&mut self, status: impl Into<SharedString>, cx: &mut Context<Self>) {
        self.status = status.into();
        cx.notify();
    }

    fn set_text_field(field: &Entity<TextField>, value: impl Into<String>, cx: &mut Context<Self>) {
        let value = value.into();
        field.update(cx, |field, cx| {
            field.content = value.into();
            field.selected_range = field.content.len()..field.content.len();
            cx.notify();
        });
    }

    fn field_text(field: &Entity<TextField>, cx: &Context<Self>) -> String {
        field.read(cx).content.to_string()
    }

    fn note_forward_settings_changed(&mut self, cx: &mut Context<Self>) {
        if let Some(session) = &self.network_session {
            session.restrict_forward_targets(&self.settings.allowed_forward_targets);
        }
        self.config_note = "端口转发列表有未保存改动；撤销/停用已作用于当前会话，新增授权需“保存并应用”。保存失败不会恢复撤销权限。".into();
        self.set_status("端口转发配置尚未保存", cx);
    }

    fn cancel_allowed_edit(&mut self, cx: &mut Context<Self>) {
        self.editing_allowed_id = None;
        Self::set_text_field(&self.allowed_name, "", cx);
        Self::set_text_field(&self.allowed_target, "", cx);
        Self::set_text_field(&self.allowed_peers, "", cx);
        cx.notify();
    }

    fn edit_allowed_target(&mut self, id: String, cx: &mut Context<Self>) {
        let Some(entry) = self
            .settings
            .allowed_forward_targets
            .iter()
            .find(|entry| entry.id == id)
        else {
            return;
        };
        let name = entry.name.clone();
        let target = entry.target.to_string();
        let peers = entry.allowed_peers.join(", ");
        self.editing_allowed_id = Some(id);
        Self::set_text_field(&self.allowed_name, name, cx);
        Self::set_text_field(&self.allowed_target, target, cx);
        Self::set_text_field(&self.allowed_peers, peers, cx);
        cx.notify();
    }

    fn save_allowed_target(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.is_saving_settings || !self.pending_tunnel_changes.is_empty() {
            return;
        }
        let name = Self::field_text(&self.allowed_name, cx).trim().to_owned();
        let target = match Self::field_text(&self.allowed_target, cx)
            .trim()
            .parse::<SocketAddr>()
        {
            Ok(target)
                if target.port() != 0
                    && !target.ip().is_unspecified()
                    && !target.ip().is_multicast() =>
            {
                target
            }
            _ => {
                self.set_status("目标地址必须是具体 IP:端口，端口范围为 1..65535", cx);
                return;
            }
        };
        if name.is_empty() || name.chars().any(char::is_control) {
            self.set_status("请输入有效的服务名称", cx);
            return;
        }
        let peers = Self::field_text(&self.allowed_peers, cx);
        let peers = peers
            .split(|ch: char| ch == ',' || ch.is_whitespace())
            .filter(|peer| !peer.is_empty())
            .map(|peer| NodeId::from_hex(peer).map(|peer| peer.to_hex()))
            .collect::<Result<Vec<_>, _>>();
        let peers = match peers {
            Ok(peers)
                if !peers.is_empty()
                    && peers.iter().collect::<std::collections::HashSet<_>>().len()
                        == peers.len() =>
            {
                peers
            }
            _ => {
                self.set_status(
                    "请输入不重复的授权设备完整 Node ID，以逗号或空格分隔；空列表不授权任何设备",
                    cx,
                );
                return;
            }
        };
        let editing_id = self.editing_allowed_id.clone();
        if self.settings.allowed_forward_targets.iter().any(|entry| {
            entry.enabled
                && entry.target == target
                && editing_id.as_deref() != Some(entry.id.as_str())
        }) {
            self.set_status(format!("已启用的允许目标重复：{target}"), cx);
            return;
        }
        if let Some(id) = editing_id {
            if let Some(entry) = self
                .settings
                .allowed_forward_targets
                .iter_mut()
                .find(|entry| entry.id == id)
            {
                entry.name = name;
                entry.target = target;
                entry.allowed_peers = peers;
            }
        } else {
            self.settings
                .allowed_forward_targets
                .push(AllowedForwardTarget::new(name, target, peers));
        }
        self.cancel_allowed_edit(cx);
        self.note_forward_settings_changed(cx);
    }

    fn toggle_allowed_target(&mut self, id: String, cx: &mut Context<Self>) {
        if self.is_saving_settings || !self.pending_tunnel_changes.is_empty() {
            return;
        }
        if let Some(entry) = self
            .settings
            .allowed_forward_targets
            .iter_mut()
            .find(|entry| entry.id == id)
        {
            entry.enabled = !entry.enabled;
            self.note_forward_settings_changed(cx);
        }
    }

    fn delete_allowed_target(&mut self, id: String, cx: &mut Context<Self>) {
        if self.is_saving_settings || !self.pending_tunnel_changes.is_empty() {
            return;
        }
        self.settings
            .allowed_forward_targets
            .retain(|entry| entry.id != id);
        if self.editing_allowed_id.as_deref() == Some(id.as_str()) {
            self.cancel_allowed_edit(cx);
        }
        self.note_forward_settings_changed(cx);
    }

    fn cancel_tunnel_edit(&mut self, cx: &mut Context<Self>) {
        self.editing_tunnel_id = None;
        Self::set_text_field(&self.tunnel_name, "", cx);
        Self::set_text_field(&self.tunnel_peer, "", cx);
        Self::set_text_field(&self.tunnel_listen, "127.0.0.1:", cx);
        Self::set_text_field(&self.tunnel_target, "", cx);
        cx.notify();
    }

    fn edit_tunnel_rule(&mut self, id: String, cx: &mut Context<Self>) {
        let Some(rule) = self.settings.tunnel_rules.iter().find(|rule| rule.id == id) else {
            return;
        };
        let name = rule.name.clone();
        let peer = rule.peer_node_id.clone();
        let listen = rule.listen.to_string();
        let target = rule.target.to_string();
        self.editing_tunnel_id = Some(id);
        Self::set_text_field(&self.tunnel_name, name, cx);
        Self::set_text_field(&self.tunnel_peer, peer, cx);
        Self::set_text_field(&self.tunnel_listen, listen, cx);
        Self::set_text_field(&self.tunnel_target, target, cx);
        cx.notify();
    }

    fn save_tunnel_rule(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.is_saving_settings || !self.pending_tunnel_changes.is_empty() {
            return;
        }
        let name = Self::field_text(&self.tunnel_name, cx).trim().to_owned();
        if name.is_empty() || name.chars().any(char::is_control) {
            self.set_status("请输入有效的转发规则名称", cx);
            return;
        }
        let peer = match NodeId::from_hex(Self::field_text(&self.tunnel_peer, cx).trim()) {
            Ok(peer)
                if self
                    .identity
                    .as_ref()
                    .is_none_or(|identity| identity.node_id() != peer) =>
            {
                peer.to_hex()
            }
            Ok(_) => {
                self.set_status("本机转发规则不能绑定本机 Node ID", cx);
                return;
            }
            Err(error) => {
                self.set_status(format!("对端 Node ID 无效：{error}"), cx);
                return;
            }
        };
        let listen = match Self::field_text(&self.tunnel_listen, cx)
            .trim()
            .parse::<SocketAddr>()
        {
            Ok(listen) if listen.ip().is_loopback() && listen.port() != 0 => listen,
            _ => {
                self.set_status("本机监听地址必须是 127.0.0.1:端口 或 [::1]:端口", cx);
                return;
            }
        };
        let target = match Self::field_text(&self.tunnel_target, cx)
            .trim()
            .parse::<SocketAddr>()
        {
            Ok(target)
                if target.port() != 0
                    && !target.ip().is_unspecified()
                    && !target.ip().is_multicast() =>
            {
                target
            }
            _ => {
                self.set_status("远端目标必须是具体 IP:端口，端口范围为 1..65535", cx);
                return;
            }
        };
        if let Some(id) = self.editing_tunnel_id.clone() {
            if let Some(rule) = self
                .settings
                .tunnel_rules
                .iter_mut()
                .find(|rule| rule.id == id)
            {
                rule.name = name;
                rule.peer_node_id = peer;
                rule.listen = listen;
                rule.target = target;
            }
        } else {
            let mut rule = TunnelRule::new(name, peer, listen.port(), target);
            rule.listen = listen;
            self.settings.tunnel_rules.push(rule);
        }
        self.cancel_tunnel_edit(cx);
        self.note_forward_settings_changed(cx);
    }

    fn revoke_tunnel_from_settings(&mut self, id: String, delete: bool, cx: &mut Context<Self>) {
        if self.is_saving_settings || !self.pending_tunnel_changes.insert(id.clone()) {
            return;
        }
        let session = self
            .network_session
            .clone()
            .filter(|session| session.is_running());
        self.set_status("正在关闭本机监听…", cx);
        cx.spawn(async move |shell, cx| {
            let result = if let Some(session) = session {
                session.revoke_tunnel_rule(id.clone(), delete).await
            } else {
                Ok(())
            };
            let _ = shell.update(cx, |shell, cx| {
                shell.pending_tunnel_changes.remove(&id);
                match result {
                    Ok(()) => {
                        if delete {
                            shell.settings.tunnel_rules.retain(|rule| rule.id != id);
                            if shell.editing_tunnel_id.as_deref() == Some(id.as_str()) {
                                shell.cancel_tunnel_edit(cx);
                            }
                        } else if let Some(rule) = shell
                            .settings
                            .tunnel_rules
                            .iter_mut()
                            .find(|rule| rule.id == id)
                        {
                            rule.enabled = false;
                        }
                        shell
                            .tunnel_states
                            .insert(id, session::TunnelRuntimeState::Stopped);
                        shell.note_forward_settings_changed(cx);
                    }
                    Err(error) => {
                        shell.set_status(format!("未完成停用/删除：{error}；规则仍保留"), cx)
                    }
                }
            });
        })
        .detach();
    }

    fn toggle_tunnel_enabled(&mut self, id: String, cx: &mut Context<Self>) {
        if self.is_saving_settings || self.pending_tunnel_changes.contains(&id) {
            return;
        }
        if self
            .settings
            .tunnel_rules
            .iter()
            .any(|rule| rule.id == id && rule.enabled)
        {
            self.revoke_tunnel_from_settings(id, false, cx);
        } else if let Some(rule) = self
            .settings
            .tunnel_rules
            .iter_mut()
            .find(|rule| rule.id == id)
        {
            rule.enabled = true;
            self.note_forward_settings_changed(cx);
        }
    }

    fn toggle_tunnel_auto_start(&mut self, id: String, cx: &mut Context<Self>) {
        if self.is_saving_settings || !self.pending_tunnel_changes.is_empty() {
            return;
        }
        if let Some(rule) = self
            .settings
            .tunnel_rules
            .iter_mut()
            .find(|rule| rule.id == id)
        {
            rule.auto_start = !rule.auto_start;
            self.note_forward_settings_changed(cx);
        }
    }

    fn delete_tunnel_rule(&mut self, id: String, cx: &mut Context<Self>) {
        self.revoke_tunnel_from_settings(id, true, cx);
    }

    fn toggle_tunnel_runtime(&mut self, id: String, cx: &mut Context<Self>) {
        if self.pending_tunnel_changes.contains(&id) {
            return;
        }
        let running = matches!(
            self.tunnel_states.get(&id),
            Some(
                session::TunnelRuntimeState::WaitingAuthorization
                    | session::TunnelRuntimeState::Starting
                    | session::TunnelRuntimeState::Running
            )
        );
        let Some(session) = self.network_session.as_ref() else {
            let detail = "请先保存信令地址并启动网络会话".to_owned();
            self.tunnel_last_errors.insert(id.clone(), detail.clone());
            self.tunnel_states
                .insert(id, session::TunnelRuntimeState::Error(detail.clone()));
            self.set_status(detail, cx);
            return;
        };
        let result = if running {
            session.stop_tunnel_rule(id)
        } else {
            session.start_tunnel_rule(id)
        };
        if let Err(error) = result {
            self.set_status(error, cx);
        }
    }

    fn start_network_session(
        &mut self,
        mut config: session::DesktopSessionConfig,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(identity) = self.identity.clone() else {
            self.network_status = "本机身份不可用；网络会话未启动".into();
            self.set_status(self.network_status.clone(), cx);
            return false;
        };
        config.remote_auth = self.settings.remote_auth.clone();
        config.signal_tls = self.settings.signal_tls.clone();
        config.trusted_devices = self.settings.trusted_devices.clone();
        config.config_path = Some(self.config_file.clone());
        config.transfer = self.transfer_service.clone();
        config.allowed_forward_targets = self.settings.enabled_forward_targets();
        config.tunnel_rules = self.settings.tunnel_rules.clone();
        match session::spawn(identity, config) {
            Ok((handle, mut session_events)) => {
                self.network_epoch = self.network_epoch.wrapping_add(1);
                let network_epoch = self.network_epoch;
                self.peer_generations.clear();
                self.peer_states.clear();
                self.peer_path_status.clear();
                self.connection_diagnostics.reset(Instant::now());
                self.network_path_status = "UDP 地址族正在准备".into();
                self.tunnel_states.clear();
                self.pending_resumes.clear();
                self.network_session = Some(handle);
                self.network_status = "正在准备 UDP 并连接信令".into();
                self.set_status(self.network_status.clone(), cx);
                cx.spawn(async move |shell, cx| {
                    while let Some(event) = session_events.recv().await {
                        if shell
                            .update(cx, |shell, cx| {
                                if shell.network_epoch != network_epoch {
                                    return;
                                }
                                match event {
                                    session::SessionEvent::SignalSecurity { tls } => {
                                        shell.connection_diagnostics.signal_security(tls, Instant::now()); cx.notify();
                                    }
                                    session::SessionEvent::NetworkFamilies { ipv4, ipv6, relay_configured } => {
                                        shell.connection_diagnostics.network_families(ipv4, ipv6, relay_configured); cx.notify();
                                    }
                                    session::SessionEvent::PeerCandidates { peer, generation, ipv4, ipv6 } => {
                                        shell.connection_diagnostics.candidates(peer, generation, ipv4, ipv6, Instant::now()); cx.notify();
                                    }
                                    session::SessionEvent::PeerTransport { peer, generation, relay, family } => {
                                        shell.connection_diagnostics.transport(peer, generation, relay, family, Instant::now()); cx.notify();
                                    }
                                    session::SessionEvent::NetworkPaths(detail) => {
                                        shell.network_path_status = detail.into(); cx.notify();
                                    }
                                    session::SessionEvent::PeerPath { peer, generation, detail } => {
                                        if ui_model::project_peer_path(&mut shell.peer_path_status, &shell.peer_generations, peer, generation, detail) { cx.notify(); }
                                    }
                                    session::SessionEvent::Lifecycle(lifecycle) => {
                                        shell.connection_diagnostics.network(&lifecycle, Instant::now());
                                        shell.signal_state.apply(&lifecycle);
                                        let label = lifecycle.label();
                                        if matches!(lifecycle,
                                            network_state::NetworkLifecycle::Unconfigured
                                            | network_state::NetworkLifecycle::ConnectingSignal
                                            | network_state::NetworkLifecycle::SignalOnline
                                            | network_state::NetworkLifecycle::ReconnectingSignal { .. }
                                            | network_state::NetworkLifecycle::Failed { .. }
                                        ) {
                                            shell.network_status = label.clone().into();
                                        }
                                        shell.set_status(label, cx);
                                    }
                                    session::SessionEvent::PeerState {
                                        peer,
                                        generation,
                                        state,
                                    } => {
                                        if shell
                                            .peer_generations
                                            .get(&peer)
                                            .is_some_and(|current| generation < *current)
                                        {
                                            return;
                                        }
                                        if !shell.peer_generations.contains_key(&peer)
                                            && shell.peer_generations.len() >= network_state::MAX_PEERS
                                            && let Some(oldest) = shell.peer_generations.iter()
                                                .min_by_key(|(_, generation)| **generation).map(|(peer, _)| *peer)
                                        {
                                            shell.peer_generations.remove(&oldest);
                                            shell.peer_states.remove(&oldest);
                                        }
                                        if shell.peer_path_status.get(&peer).is_some_and(|(g, _)| *g < generation)
                                            || matches!(state, network_state::PeerLifecycle::Disconnected | network_state::PeerLifecycle::Failed(_)) {
                                            shell.peer_path_status.remove(&peer);
                                        }
                                        shell.peer_generations.insert(peer, generation);
                                        shell.connection_diagnostics.peer(peer, generation, &state, Instant::now());
                                        shell.peer_states.insert(peer, state.clone());
                                        if state.outbound_authorized() {
                                            if let Some(ids)=shell.pending_resumes.remove(&peer) {
                                                for id in ids {if let Some(session)=&shell.network_session && let Err(e)=session.resume_task(peer,id){shell.set_status(e,cx);}}
                                            }
                                        }else if matches!(state,network_state::PeerLifecycle::Disconnected|network_state::PeerLifecycle::Failed(_)){shell.pending_resumes.remove(&peer);}
                                        let label = match state {
                                            network_state::PeerLifecycle::PeerPending => {
                                                "等待对端候选地址".to_owned()
                                            }
                                            network_state::PeerLifecycle::Punching => {
                                                "正在探测 UDP 可达性".to_owned()
                                            }
                                            network_state::PeerLifecycle::Authenticating => {
                                                "正在执行 QUIC 与身份认证".to_owned()
                                            }
                                            network_state::PeerLifecycle::Negotiating => {
                                                "正在协商桌面版本与能力".to_owned()
                                            }
                                            network_state::PeerLifecycle::RemoteAuthPending => { "身份已认证，等待远程密码授权".to_owned() }
                                            network_state::PeerLifecycle::Connected(auth) => auth.label().to_owned(),
                                            network_state::PeerLifecycle::Disconnected => {
                                                "连接已断开".to_owned()
                                            }
                                            network_state::PeerLifecycle::Failed(detail) => {
                                                format!("连接失败：{detail}")
                                            }
                                        };
                                        let message = format!("对端 {}：{label}", peer.short());
                                        shell.peer_status = message.clone().into();
                                        shell.set_status(message, cx);
                                    }
                                    session::SessionEvent::ShortIdRegistered(id) => {shell.local_short_id = Some(id); cx.notify();}
                                    session::SessionEvent::ShortIdResolved {short_id, peer} => {
                                        let text = shell.peer_id.read(cx).content.trim().to_owned();
                                        if ShortId::normalize(&text).ok() == Some(short_id) {
                                            shell.resolved_peer = peer.map(|peer| (text,peer));
                                            if peer.is_none() {shell.set_status("短 ID 无法解析或查询暂时受限",cx);}
                                        }
                                    }
                                    session::SessionEvent::SignalIdentityRegistered(peer) => {
                                        let label =
                                            format!("信令在线；已登记本机身份 {}", peer.short());
                                        shell.network_status = label.clone().into();
                                        shell.set_status(label, cx);
                                    }
                                    session::SessionEvent::SelectionQueued {peer,count}=>{shell.set_status(format!("扫描已完成，{count} 项已入队，绑定对端 {}",peer.to_hex()),cx);}
                                    session::SessionEvent::SpeedRequestEnded {peer}=>{if shell.speed_peer==Some(peer){shell.speed_request_until=None;}cx.notify();}
                                    session::SessionEvent::SpeedPhaseCompleted { peer, snapshot } => {
                                        if shell.speed_peer == Some(peer) {
                                            if snapshot.direction == protocol::SpeedDirection::Upload
                                                && snapshot.status == speed::SpeedStatus::Completed
                                                && shell.identity.as_ref().is_some_and(|identity| identity.node_id() == snapshot.owner)
                                            {
                                                shell.speedtest_upload_result = Some(snapshot);
                                                if shell.settings.speedtest_direction == SpeedtestDirection::Both {
                                                    shell.set_status("上传阶段完成，正在进行下载阶段…", cx);
                                                }
                                            } else if snapshot.direction == protocol::SpeedDirection::Download
                                                && snapshot.status == speed::SpeedStatus::Completed
                                                && shell.settings.speedtest_direction == SpeedtestDirection::Both
                                            {
                                                shell.set_status("双向速度测试已完成", cx);
                                            }
                                            cx.notify();
                                        }
                                    }
                                    session::SessionEvent::TrustedDevicesChanged(devices) => { shell.settings.trusted_devices = devices; cx.notify(); }
                            session::SessionEvent::Diagnostic(detail) => {
                                        if detail != "信令心跳已确认" {shell.set_status(detail, cx);}
                                    }
                                    session::SessionEvent::TunnelState { rule_id, state } => {
                                        if let session::TunnelRuntimeState::Error(detail) = &state {
                                            shell.tunnel_last_errors.insert(rule_id.clone(), detail.clone());
                                        } else if matches!(
                                            &state,
                                            session::TunnelRuntimeState::Starting
                                                | session::TunnelRuntimeState::Running
                                        ) {
                                            shell.tunnel_last_errors.remove(&rule_id);
                                        }
                                        shell.tunnel_states.insert(rule_id, state);
                                        cx.notify();
                                    }
                                    session::SessionEvent::TunnelError { rule_id, detail } => {
                                        shell.tunnel_last_errors.insert(rule_id, detail.clone());
                                        shell.set_status(detail, cx);
                                        cx.notify();
                                    }
                                }
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                })
                .detach();
                true
            }
            Err(error) => {
                let detail = format!("创建网络会话失败：{error}");
                self.network_status = detail.clone().into();
                self.set_status(detail, cx);
                false
            }
        }
    }

    fn connect_peer(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.connect_current_peer(cx);
    }
    fn connect_current_peer(&mut self, cx: &mut Context<Self>) {
        let text = self.peer_id.read(cx).content.trim().to_owned();
        let input = self.peer_password.read(cx).content.to_string();
        let password = match if input.is_empty() {
            Ok(None)
        } else {
            SecretPassword::new(input).map(Some)
        } {
            Ok(password) => password,
            Err(error) => {
                self.set_status(error.to_string(), cx);
                return;
            }
        };
        let Some(session) = self.network_session.as_ref() else {
            self.set_status("请先保存有效的信令配置", cx);
            return;
        };
        let result = if let Ok(short_id) = ShortId::normalize(&text) {
            if self.local_short_id == Some(short_id) {
                self.set_status("不能连接本机设备 ID", cx);
                return;
            }
            self.resolved_peer = None;
            match password {
                Some(password) => session.connect_short_id(short_id, password),
                None => session.connect_short_id_trusted(short_id),
            }
        } else if let Ok(peer) = NodeId::from_hex(&text) {
            if self.identity.as_ref().is_some_and(|i| i.node_id() == peer) {
                self.set_status("不能连接本机设备 ID", cx);
                return;
            }
            match password {
                Some(password) => session.connect_peer_with_password(peer, password),
                None => session.connect_peer_trusted(peer),
            }
        } else {
            self.set_status("设备 ID 须为 9 位短 ID 或完整 Node ID", cx);
            return;
        };
        match result {
            Ok(()) => self.set_status("正在查询设备并建立认证连接", cx),
            Err(error) => self.set_status(error, cx),
        }
    }
    fn save_remote_password(&mut self, regenerate: bool, cx: &mut Context<Self>) {
        if !self.can_save_settings || self.is_saving_settings {
            return;
        }
        let password = if regenerate {
            SecretPassword::generate()
        } else {
            SecretPassword::new(self.local_password.read(cx).content.to_string())
        };
        let password = match password {
            Ok(password) => password,
            Err(error) => {
                self.set_status(error.to_string(), cx);
                return;
            }
        };
        let path = self.config_file.clone();
        let session = self.network_session.clone();
        let background = cx.background_executor().clone();
        self.is_saving_settings = true;
        self.set_status("正在保存远程密码并撤销已有会话授权…", cx);
        cx.spawn(async move |shell, cx| {
            let result = background
                .spawn(async move {
                    let verifier = RemoteVerifier::create(&password).map_err(|e| e.to_string())?;
                    DesktopConfig::save_remote_auth(&path, verifier.clone())
                        .map_err(|e| e.to_string())?;
                    let applied = if let Some(session) = session {
                        session.update_remote_auth(verifier.clone()).await
                    } else {
                        Ok(())
                    };
                    Ok::<_, String>((verifier, password, applied))
                })
                .await;
            let _ = shell.update(cx, |shell, cx| {
                shell.is_saving_settings = false;
                match result {
                    Ok((verifier, password, applied)) => {
                        shell.settings.remote_auth = Some(verifier);
                        shell.peer_states.clear();
                        shell.pending_resumes.clear();
                        shell.local_password.update(cx, |field, cx| {
                            field.content = password.expose().to_owned().into();
                            field.revealed = false;
                            field.marked_range = None;
                            field.selection_reversed = false;
                            field.is_selecting = false;
                            field.selected_range = field.content.len()..field.content.len();
                            field.last_layout = None;
                            cx.notify();
                        });
                        match applied {
                            Ok(()) => {
                                shell.set_status("远程密码已保存；已有会话已撤销，请重新连接", cx)
                            }
                            Err(_) => {
                                if let Some(session) = shell.network_session.take() {
                                    session.shutdown();
                                }
                                shell.set_status("密码已保存；网络会话已关闭，请重新启动网络", cx);
                            }
                        }
                    }
                    Err(error) => shell
                        .set_status(format!("密码保存未确认；当前会话仍使用原密码：{error}"), cx),
                }
            });
        })
        .detach();
    }
    fn remote_password_card(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let enabled = self.can_save_settings && !self.is_saving_settings;
        ui_components::card()
            .child(ui_components::section_header(
                "🔑",
                "远程访问密码",
                "首次生成后请复制保存；重启后不能从派生密钥回显密码",
            ))
            .child(Self::text_field_frame(&self.local_password, window, cx))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        ui_components::secondary_button(
                            if self.local_password.read(cx).revealed {
                                "隐藏"
                            } else {
                                "显示"
                            },
                            true,
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(|shell, _, _, cx| {
                                shell.local_password.update(cx, |field, cx| {
                                    field.revealed = !field.revealed;
                                    field.last_layout = None;
                                    cx.notify();
                                });
                            }),
                        ),
                    )
                    .child(
                        ui_components::secondary_button(
                            "复制",
                            !self.local_password.read(cx).content.is_empty(),
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(|shell, _, _, cx| {
                                let value = shell.local_password.read(cx).content.to_string();
                                if !value.is_empty() {
                                    cx.write_to_clipboard(ClipboardItem::new_string(value));
                                    shell.set_status("已复制密码，请妥善保存", cx);
                                }
                            }),
                        ),
                    )
                    .child(
                        ui_components::secondary_button("保存新密码", enabled).on_mouse_up(
                            MouseButton::Left,
                            cx.listener(|shell, _, _, cx| shell.save_remote_password(false, cx)),
                        ),
                    )
                    .child(
                        ui_components::secondary_button("重新生成", enabled).on_mouse_up(
                            MouseButton::Left,
                            cx.listener(|shell, _, _, cx| shell.save_remote_password(true, cx)),
                        ),
                    ),
            )
    }
    fn copy_short_id(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(id) = self.local_short_id {
            cx.write_to_clipboard(ClipboardItem::new_string(id.to_string()));
            self.set_status("已复制本机短设备 ID", cx);
        }
    }

    fn change_concurrency(&mut self, cx: &mut Context<Self>) {
        if self.is_saving_settings {
            return;
        }
        let next = self.settings.send_concurrency % 3 + 1;
        self.set_send_concurrency(next, cx);
    }
    fn sync_concurrency_input(&mut self, value: u8, cx: &mut Context<Self>) {
        let value_text = value.to_string();
        if self.concurrency_input.read(cx).content.as_ref() != value_text.as_str() {
            self.concurrency_input.update(cx, |input, cx| {
                input.content = value_text.into();
                let cursor = input.content.len();
                input.selected_range = cursor..cursor;
                input.marked_range = None;
                cx.notify();
            });
        }
    }
    fn set_send_concurrency(&mut self, value: u8, cx: &mut Context<Self>) {
        if !(1..=3).contains(&value) {
            return;
        }
        if self.is_saving_settings {
            let saved_value = self.settings.send_concurrency;
            self.sync_concurrency_input(saved_value, cx);
            return;
        }
        let changed = self.settings.send_concurrency != value;
        self.settings.send_concurrency = value;
        self.sync_concurrency_input(value, cx);
        if changed
            && let Some(service) = self.transfer_service.as_ref()
            && let Err(error) = service.set_send_limit(value)
        {
            self.set_status(format!("并发设置失败：{error}"), cx);
            return;
        }
        cx.notify();
    }

    fn change_duration(&mut self, cx: &mut Context<Self>) {
        if self.is_saving_settings {
            return;
        }
        self.settings.speedtest_seconds = if self.settings.speedtest_seconds == 30 {
            60
        } else if self.settings.speedtest_seconds >= 600 {
            30
        } else {
            self.settings.speedtest_seconds + 60
        };
        cx.notify();
    }

    fn change_direction(&mut self, cx: &mut Context<Self>) {
        if self.is_saving_settings {
            return;
        }
        self.settings.speedtest_direction = match self.settings.speedtest_direction {
            SpeedtestDirection::Both => SpeedtestDirection::Upload,
            SpeedtestDirection::Upload => SpeedtestDirection::Download,
            SpeedtestDirection::Download => SpeedtestDirection::Both,
        };
        self.speedtest_upload_result = None;
        cx.notify();
    }

    fn set_speed_direction(&mut self, direction: SpeedtestDirection, cx: &mut Context<Self>) {
        if self.is_saving_settings
            || self.speed_request_until.is_some()
            || self
                .speed_views
                .0
                .values()
                .any(|view| view.snapshot.status == speed::SpeedStatus::Running)
        {
            return;
        }
        if self.settings.speedtest_direction == direction {
            return;
        }
        self.settings.speedtest_direction = direction;
        self.speedtest_upload_result = None;
        cx.notify();
    }

    fn speed_direction_button(
        &self,
        id: &'static str,
        label: &'static str,
        direction: SpeedtestDirection,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let selected = self.settings.speedtest_direction == direction;
        let enabled = !self.is_saving_settings
            && self.speed_request_until.is_none()
            && !self
                .speed_views
                .0
                .values()
                .any(|view| view.snapshot.status == speed::SpeedStatus::Running);
        div()
            .id(id)
            .h(px(36.))
            .px(px(12.))
            .flex()
            .items_center()
            .justify_center()
            .rounded_md()
            .border_1()
            .border_color(rgb(if selected {
                ui_theme::PRIMARY
            } else {
                ui_theme::BORDER
            }))
            .bg(rgb(if selected {
                ui_theme::PRIMARY
            } else {
                ui_theme::SURFACE_SUBTLE
            }))
            .text_sm()
            .text_color(rgb(if selected {
                ui_theme::SURFACE
            } else {
                ui_theme::TEXT
            }))
            .when(enabled, |button| button.cursor(CursorStyle::PointingHand))
            .child(label)
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                    shell.set_speed_direction(direction, cx)
                }),
            )
    }

    fn save_settings(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.persist_settings(cx);
    }
    fn persist_settings(&mut self, cx: &mut Context<Self>) {
        if !self.pending_tunnel_changes.is_empty() {
            self.set_status("请等待本机监听关闭后再保存", cx);
            return;
        }
        if !self.can_save_settings || self.is_saving_settings {
            self.set_status("当前配置不可保存；请检查配置诊断信息", cx);
            return;
        }

        let mut draft = self.settings.clone();
        draft.signal_host = self.signal_host.read(cx).content.to_string();
        draft.signal_port = self.signal_port.read(cx).content.to_string();
        draft.signal_tls = self.signal_tls_enabled.then(|| {
            let ca = self.signal_ca_file.read(cx).content.trim().to_owned();
            let name = self.signal_server_name.read(cx).content.trim().to_owned();
            crate::discovery::signal_tls::SignalTlsClient {
                ca_file: (!ca.is_empty()).then(|| PathBuf::from(ca)),
                server_name: (!name.is_empty()).then_some(name),
            }
        });
        let relay = self.relay_server.read(cx).content.trim().to_owned();
        draft.relay_server = (!relay.is_empty()).then_some(relay);
        let relay_server = draft.relay_server.clone();
        let config_file = self.config_file.clone();
        let signal_server = signal_server_spec(&draft.signal_host, &draft.signal_port);
        let saved_receive_root = draft.receive_directory.clone();
        let saved_send_limit = draft.send_concurrency;
        let signal_changed = draft.signal_host != self.settings.signal_host
            || draft.signal_port != self.settings.signal_port
            || draft.relay_server != self.settings.relay_server
            || draft.signal_tls != self.settings.signal_tls;
        let saved_draft = draft.clone();
        let background = cx.background_executor().clone();
        self.is_saving_settings = true;
        self.set_status("正在验证并保存设置…", cx);

        cx.spawn(async move |shell, cx| {
            let result = background
                .spawn(async move { draft.save_atomic(&config_file) })
                .await;
            shell
                .update(cx, |shell, cx| {
                    shell.is_saving_settings = false;
                    match result {
                        Ok(()) => {
                            shell.settings = saved_draft;
                            shell.applied_receive_root = saved_receive_root.clone();
                            shell.config_note = "设置已保存；端口转发配置已应用。".into();
                            if let (Some(service), Some(root)) =
                                (&shell.transfer_service, &saved_receive_root)
                            {
                                service.set_receive_root(root.clone());
                            }
                            if let Some(service) = shell.transfer_service.as_ref()
                                && let Err(error) = service.set_send_limit(saved_send_limit)
                            {
                                shell.set_status(error.to_string(), cx);
                                return;
                            }
                            let mut started = false;
                            if let Some(session) = shell
                                .network_session
                                .as_ref()
                                .filter(|session| session.is_running())
                            {
                                if let Err(error) = session.update_tunnel_settings(
                                    shell.settings.enabled_forward_targets(),
                                    shell.settings.tunnel_rules.clone(),
                                ) {
                                    shell.set_status(
                                        format!("设置已保存；端口转发应用失败：{error}"),
                                        cx,
                                    );
                                    return;
                                }
                                if !signal_changed {
                                    shell.set_status("设置已保存；现有任务和连接继续运行", cx);
                                    return;
                                }
                                match session.reconfigure_network(
                                    signal_server.clone(),
                                    relay_server.clone(),
                                    shell.settings.signal_tls.clone(),
                                ) {
                                    Ok(()) => {
                                        shell.network_status = "正在使用新信令配置重连".into();
                                        shell.set_status(shell.network_status.clone(), cx);
                                        started = true;
                                    }
                                    Err(error) => {
                                        shell.set_status(
                                            format!("设置已保存；网络重配置失败：{error}"),
                                            cx,
                                        );
                                        return;
                                    }
                                }
                            }
                            if !started {
                                shell.network_session = None;
                                let mut config = session::DesktopSessionConfig::new(signal_server);
                                config.network.relay_server = relay_server;
                                config.allowed_forward_targets =
                                    shell.settings.enabled_forward_targets();
                                config.tunnel_rules = shell.settings.tunnel_rules.clone();
                                shell.start_network_session(config, cx);
                            }
                        }
                        Err(error) => {
                            shell.set_status(
                                format!(
                                    "设置未保存：{error}；新增授权未应用，已执行的撤销/停用保持生效"
                                ),
                                cx,
                            );
                        }
                    }
                })
                .ok();
        })
        .detach();
    }

    fn drop_admission(&self, cx: &Context<Self>) -> drop_send::Admission {
        drop_send::Admission {
            authorized: self.selected_peer(cx).is_some_and(|peer| {
                self.peer_states
                    .get(&peer)
                    .is_some_and(network_state::PeerLifecycle::outbound_authorized)
            }),
            storage_ready: self.transfer_service.is_some() && self.network_session.is_some(),
            modal: self.show_settings_home
                || self.show_settings
                || self.show_diagnostics
                || self.native_dialogs > 0
                || self.clearing_history
                || self.exporting_diagnostics
                || self.is_saving_settings,
            speed_busy: self.speed_request_until.is_some()
                || self
                    .speed_views
                    .0
                    .values()
                    .any(|view| view.snapshot.status == speed::SpeedStatus::Running),
        }
    }
    fn drop_paths(&mut self, paths: &gpui::ExternalPaths, _: &mut Window, cx: &mut Context<Self>) {
        if !self.drop_admission(cx).allowed() {
            self.set_status(
                "当前不能拖入：请完成设备授权，关闭设置或对话框，并等待测速结束",
                cx,
            );
            return;
        }
        if let Err(error) = drop_send::validate_paths(paths.paths()) {
            self.set_status(error.to_string(), cx);
            return;
        }
        let Some(peer) = self.authenticated_peer(cx) else {
            return;
        };
        let count = paths.paths().len();
        let result = self
            .network_session
            .as_ref()
            .ok_or_else(|| "网络会话已关闭".to_owned())
            .and_then(|session| session.send_paths(peer, paths.paths().to_vec()));
        match result {
            Ok(()) => self.set_status(format!("正在后台检查 {count} 个拖入项；发送设备 {} 已固定，重复与目录内子路径只发送一次", peer.short()), cx),
            Err(error) => self.set_status(format!("拖入项尚未提交：{error}"), cx),
        }
    }
    fn choose_files(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.pick_files(cx);
    }
    fn pick_files(&mut self, cx: &mut Context<Self>) {
        if self.native_dialogs > 0 {
            self.set_status("请先关闭当前文件对话框", cx);
            return;
        }
        if self
            .speed_views
            .0
            .values()
            .any(|v| v.snapshot.status == speed::SpeedStatus::Running)
        {
            self.set_status("测速正在进行，请先取消或等待完成后添加文件", cx);
            return;
        }
        let Some(peer) = self.authenticated_peer(cx) else {
            return;
        };
        let epoch = self.network_epoch;
        self.native_dialogs += 1;
        cx.notify();
        let task = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: Some("选择要发送的文件".into()),
        });
        cx.spawn(async move |shell, cx| {
            let result = task.await;
            shell
                .update(cx, |shell, cx| {
                    shell.native_dialogs = shell.native_dialogs.saturating_sub(1);
                    match result {
                        Ok(Ok(Some(paths))) if paths.iter().any(|path| path.to_str().is_none()) => {
                            shell.set_status("所选文件路径编码不受支持；未保存或转换该路径", cx);
                        }
                        Ok(Ok(Some(paths))) if !paths.is_empty() => {
                            let count = paths.len();
                            if shell.network_epoch != epoch {
                                shell.set_status("选择期间网络会话已重建，请重新选择", cx);
                                return;
                            }
                            let result = shell
                                .network_session
                                .as_ref()
                                .ok_or("网络会话已关闭".to_owned())
                                .and_then(|session| {
                                    for path in &paths {
                                        session.send_file(peer, path.clone())?;
                                    }
                                    Ok(())
                                });
                            shell.selected_files = paths;
                            match result {
                                Ok(()) => shell.set_status(
                                    format!(
                                        "正在后台扫描 {count} 个文件；发送对象 {} 已固定",
                                        peer.to_hex()
                                    ),
                                    cx,
                                ),
                                Err(e) => shell.set_status(
                                    format!("文件提交未全部完成：{e}；已提交项将在任务列表中显示"),
                                    cx,
                                ),
                            }
                        }
                        Ok(Ok(None)) => shell.set_status("已取消文件选择", cx),
                        Ok(Ok(Some(_))) => shell.set_status("未选择文件", cx),
                        Ok(Err(error)) => shell.set_status(format!("文件选择失败：{error:?}"), cx),
                        Err(_) => shell.set_status("文件选择任务已取消", cx),
                    }
                })
                .ok();
        })
        .detach();
    }

    fn choose_folder(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.pick_folder(cx);
    }
    fn pick_folder(&mut self, cx: &mut Context<Self>) {
        if self.native_dialogs > 0 {
            self.set_status("请先关闭当前文件对话框", cx);
            return;
        }
        if self
            .speed_views
            .0
            .values()
            .any(|v| v.snapshot.status == speed::SpeedStatus::Running)
        {
            self.set_status("测速正在进行，请先取消或等待完成后添加文件", cx);
            return;
        }
        let Some(peer) = self.authenticated_peer(cx) else {
            return;
        };
        let epoch = self.network_epoch;
        self.native_dialogs += 1;
        cx.notify();
        let task = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("选择要发送的目录".into()),
        });
        cx.spawn(async move |shell, cx| {
            let result = task.await;
            shell
                .update(cx, |shell, cx| {
                    shell.native_dialogs = shell.native_dialogs.saturating_sub(1);
                    match result {
                        Ok(Ok(Some(mut paths))) => {
                            if let Some(path) = paths.pop() {
                                if let Some(path_text) = path.to_str() {
                                    if shell.network_epoch != epoch {
                                        shell.set_status("选择期间网络会话已重建，请重新选择", cx);
                                        return;
                                    }
                                    let result = shell
                                        .network_session
                                        .as_ref()
                                        .ok_or("网络会话已关闭".to_owned())
                                        .and_then(|session| {
                                            session.send_directory(peer, path.clone())
                                        });
                                    shell.selected_folder = Some(path.clone());
                                    match result {
                                        Ok(()) => shell.set_status(
                                            format!(
                                                "正在后台扫描目录 {path_text}；发送对象 {} 已固定",
                                                peer.to_hex()
                                            ),
                                            cx,
                                        ),
                                        Err(e) => shell.set_status(e, cx),
                                    }
                                } else {
                                    shell.set_status(
                                        "所选目录路径编码不受支持；未保存或转换该路径",
                                        cx,
                                    );
                                }
                            } else {
                                shell.set_status("未选择目录", cx);
                            }
                        }
                        Ok(Ok(None)) => shell.set_status("已取消目录选择", cx),
                        Ok(Err(error)) => shell.set_status(format!("目录选择失败：{error:?}"), cx),
                        Err(_) => shell.set_status("目录选择任务已取消", cx),
                    }
                })
                .ok();
        })
        .detach();
    }

    fn choose_receive_directory(
        &mut self,
        _: &MouseUpEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.pick_receive_directory(cx);
    }
    fn pick_receive_directory(&mut self, cx: &mut Context<Self>) {
        if self.native_dialogs > 0 {
            self.set_status("请先关闭当前文件对话框", cx);
            return;
        }
        self.native_dialogs += 1;
        cx.notify();
        let task = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("选择接收目录".into()),
        });
        cx.spawn(async move |shell, cx| {
            let result = task.await;
            shell
                .update(cx, |shell, cx| {
                    shell.native_dialogs = shell.native_dialogs.saturating_sub(1);
                    match result {
                        Ok(Ok(Some(mut paths))) => {
                            if let Some(path) = paths.pop() {
                                if let Some(path_text) = path.to_str() {
                                    shell.settings.receive_directory = Some(path.to_path_buf());
                                    shell.config_note =
                                        "已选择新接收目录；保存时重新验证写能力，仅影响新任务"
                                            .into();
                                    shell.set_status(
                                        format!("接收目录已选择 {path_text}；保存后用于新任务"),
                                        cx,
                                    );
                                } else {
                                    shell.set_status(
                                        "所选接收目录路径编码不受支持；请改选其它目录",
                                        cx,
                                    );
                                }
                            } else {
                                shell.set_status("未选择接收目录", cx);
                            }
                        }
                        Ok(Ok(None)) => shell.set_status("已取消接收目录选择", cx),
                        Ok(Err(error)) => {
                            shell.set_status(format!("接收目录选择失败：{error:?}"), cx)
                        }
                        Err(_) => shell.set_status("接收目录选择任务已取消", cx),
                    }
                })
                .ok();
        })
        .detach();
    }

    fn text_field_frame(
        field: &Entity<TextField>,
        window: &Window,
        cx: &Context<Self>,
    ) -> gpui::Div {
        let focused = field.focus_handle(cx).is_focused(window);
        let frame = div()
            .w_full()
            .h(px(44.))
            .flex()
            .items_center()
            .px(px(10.))
            .bg(white())
            .border_1()
            .rounded_md()
            .child(field.clone());
        if focused {
            frame.border_color(rgb(ui_theme::PRIMARY))
        } else {
            frame.border_color(rgb(ui_theme::BORDER))
        }
    }

    fn compact_text_field_frame(
        field: &Entity<TextField>,
        window: &Window,
        cx: &Context<Self>,
    ) -> gpui::Div {
        let focused = field.focus_handle(cx).is_focused(window);
        let frame = div()
            .w(px(42.))
            .h(px(28.))
            .flex()
            .items_center()
            .px(px(4.))
            .bg(white())
            .border_1()
            .rounded_md()
            .child(field.clone());
        if focused {
            frame.border_color(rgb(ui_theme::PRIMARY))
        } else {
            frame.border_color(rgb(ui_theme::BORDER))
        }
    }

    fn save_settings_button(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let label = if self.is_saving_settings {
            "正在保存…"
        } else {
            "保存并应用"
        };
        ui_components::primary_button(label, self.can_save_settings && !self.is_saving_settings)
            .on_mouse_up(MouseButton::Left, cx.listener(Self::save_settings))
    }

    fn connect_peer_button(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let peer_is_valid = self.selected_peer(cx).is_some_and(|peer| {
            self.identity
                .as_ref()
                .is_none_or(|identity| identity.node_id() != peer)
        });
        let peer_is_active = self
            .selected_peer(cx)
            .and_then(|peer| self.peer_states.get(&peer))
            .is_some_and(|state| {
                state.is_active() && (!state.is_connected() || state.outbound_authorized())
            });
        let peer_is_valid = peer_is_valid
            || ShortId::normalize(self.peer_id.read(cx).content.trim())
                .is_ok_and(|id| self.local_short_id != Some(id));
        let password_valid = self.peer_password.read(cx).content.is_empty()
            || SecretPassword::new(self.peer_password.read(cx).content.to_string()).is_ok();
        let enabled = self.identity.is_some()
            && self.network_session.is_some()
            && password_valid
            && peer_is_valid
            && !peer_is_active;
        ui_components::primary_button("连接", enabled)
            .on_mouse_up(MouseButton::Left, cx.listener(Self::connect_peer))
    }

    fn header_status(&self, cx: &Context<Self>) -> (String, ui_components::StatusTone) {
        if let Some(peer) = self.selected_peer(cx) {
            match self.peer_states.get(&peer) {
                Some(network_state::PeerLifecycle::Connected(auth)) => {
                    return (
                        auth.label(),
                        if auth.inbound_authorized() || auth.outbound_authorized() {
                            ui_components::StatusTone::Success
                        } else {
                            ui_components::StatusTone::Warning
                        },
                    );
                }
                Some(network_state::PeerLifecycle::PeerPending) => {
                    return ("等待对端".into(), ui_components::StatusTone::Info);
                }
                Some(network_state::PeerLifecycle::Punching) => {
                    return ("正在直连".into(), ui_components::StatusTone::Info);
                }
                Some(network_state::PeerLifecycle::Authenticating) => {
                    return ("正在认证".into(), ui_components::StatusTone::Info);
                }
                Some(network_state::PeerLifecycle::RemoteAuthPending) => {
                    return (
                        "正在验证密码或可信设备授权".into(),
                        ui_components::StatusTone::Info,
                    );
                }
                Some(network_state::PeerLifecycle::Negotiating) => {
                    return ("正在协商".into(), ui_components::StatusTone::Info);
                }
                Some(network_state::PeerLifecycle::Disconnected) => {
                    return ("连接已断开".into(), ui_components::StatusTone::Warning);
                }
                Some(network_state::PeerLifecycle::Failed(_)) => {
                    return ("连接失败".into(), ui_components::StatusTone::Danger);
                }
                None => {}
            }
        }

        if self.peer_states.values().any(|state| state.is_connected()) {
            ("设备已连接".into(), ui_components::StatusTone::Success)
        } else if self.network_status.starts_with("信令在线") {
            ("信令在线".into(), ui_components::StatusTone::Success)
        } else if self.network_status.contains("失败") || self.network_status.contains("不可用")
        {
            ("网络异常".into(), ui_components::StatusTone::Danger)
        } else if self.network_status.contains("正在") || self.network_status.contains("重连") {
            ("连接中".into(), ui_components::StatusTone::Info)
        } else if self.network_session.is_none() {
            ("未配置".into(), ui_components::StatusTone::Neutral)
        } else {
            ("等待对端".into(), ui_components::StatusTone::Neutral)
        }
    }

    fn app_header(&self, cx: &mut Context<Self>) -> gpui::Div {
        let (status, tone) = self.header_status(cx);
        div()
            .h(px(56.))
            .flex()
            .items_center()
            .justify_between()
            .gap_3()
            .child(Self::brand_identity("P2P File", "设备之间，直接传文件"))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(ui_components::status_badge(status, tone))
                    .child(
                        ui_components::secondary_button("连接诊断", true).on_mouse_up(
                            MouseButton::Left,
                            cx.listener(|shell, _: &MouseUpEvent, _, cx| {
                                shell.show_diagnostics = !shell.show_diagnostics;
                                cx.notify();
                            }),
                        ),
                    )
                    .child(ui_components::secondary_button("设置", true).on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|shell, _: &MouseUpEvent, _, cx| shell.open_settings_home(cx)),
                    )),
            )
    }

    fn diagnostics_card(&self, cx: &mut Context<Self>) -> gpui::Div {
        let text = self.connection_diagnostics.text(Instant::now());
        let mut body = div()
            .id("connection-diagnostics-body")
            .max_h(px(260.))
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_1();
        for line in text.lines().skip(1) {
            body = body.child(
                div()
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child(line.to_owned()),
            );
        }
        ui_components::card()
            .flex_shrink_0()
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .gap_3()
                    .child(ui_components::section_header(
                        "⌕",
                        "连接诊断",
                        "只显示已观察阶段；缺失数据为未知",
                    ))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                ui_components::compact_secondary_button("复制脱敏摘要", true)
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(|shell, _, _, cx| {
                                            cx.write_to_clipboard(ClipboardItem::new_string(
                                                shell.connection_diagnostics.text(Instant::now()),
                                            ));
                                            shell.set_status("已复制脱敏连接诊断", cx);
                                        }),
                                    ),
                            )
                            .child(
                                ui_components::compact_secondary_button(
                                    "导出新文件",
                                    !self.exporting_diagnostics,
                                )
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(|shell, _, _, cx| shell.export_diagnostics(cx)),
                                ),
                            ),
                    ),
            )
            .child(body)
    }
    fn export_diagnostics(&mut self, cx: &mut Context<Self>) {
        if self.exporting_diagnostics {
            return;
        }
        let text = self.connection_diagnostics.text(Instant::now());
        let directory = self
            .settings
            .receive_directory
            .clone()
            .unwrap_or_else(std::env::temp_dir);
        let picked = cx.prompt_for_new_path(&directory, Some("p2p-connection-diagnostics.txt"));
        self.exporting_diagnostics = true;
        cx.notify();
        let executor = cx.background_executor().clone();
        cx.spawn(async move |shell, cx| {
            let result = match picked.await {
                Ok(Ok(Some(path))) => Some(
                    executor
                        .spawn(async move { diagnostics::export(&path, &text) })
                        .await,
                ),
                Ok(Ok(None)) => None,
                _ => Some(Err(std::io::Error::other("file picker unavailable"))),
            };
            let _ = shell.update(cx, move |shell, cx| {
                shell.exporting_diagnostics = false;
                match result {
                    Some(Ok(())) => shell.set_status("脱敏诊断已导出到所选新文件", cx),
                    Some(Err(_)) => shell.set_status(
                        "诊断导出失败；请选择新文件名或可写目录，既有文件不会被覆盖",
                        cx,
                    ),
                    None => cx.notify(),
                }
            });
        })
        .detach();
    }
    fn brand_identity(title: &'static str, subtitle: &'static str) -> gpui::Div {
        static ICON: std::sync::OnceLock<std::sync::Arc<gpui::Image>> = std::sync::OnceLock::new();
        let icon = ICON
            .get_or_init(|| {
                std::sync::Arc::new(gpui::Image::from_bytes(
                    gpui::ImageFormat::Png,
                    include_bytes!("../../assets/icons/app-icon-ui.png").to_vec(),
                ))
            })
            .clone();
        div()
            .flex()
            .items_center()
            .gap_3()
            .child(gpui::img(icon).w(px(40.)).h(px(40.)).flex_shrink_0())
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_size(px(24.))
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_color(rgb(ui_theme::TEXT))
                            .child(title),
                    )
                    .child(
                        div()
                            .text_size(px(13.))
                            .text_color(rgb(ui_theme::TEXT_SECONDARY))
                            .child(subtitle),
                    ),
            )
    }

    fn can_trust_peer(&self, peer: NodeId) -> bool {
        ui_model::can_trust_peer(
            peer,
            self.identity.as_ref().map(Identity::node_id),
            self.peer_states.get(&peer),
            &self.settings.trusted_devices,
        ) && self
            .network_session
            .as_ref()
            .is_some_and(session::DesktopSessionHandle::is_running)
            && self.peer_generations.contains_key(&peer)
            && self.can_save_settings
            && !self.is_saving_settings
    }
    fn trust_peer_button(&self, peer: NodeId, cx: &mut Context<Self>) -> impl IntoElement {
        let enabled = self.can_trust_peer(peer);
        ui_components::secondary_button("信任此设备", enabled).on_mouse_up(
            MouseButton::Left,
            cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                if !shell.can_trust_peer(peer) {
                    return;
                }
                shell.change_trusted_device(
                    session::TrustedDeviceChange::Trust {
                        peer,
                        generation: shell.peer_generations[&peer],
                        display_name: format!("设备 {}", peer.short()),
                    },
                    cx,
                );
            }),
        )
    }
    fn change_trusted_device(
        &mut self,
        change: session::TrustedDeviceChange,
        cx: &mut Context<Self>,
    ) {
        if !self.can_save_settings || self.is_saving_settings {
            return;
        }
        let session = self.network_session.clone();
        let path = self.config_file.clone();
        let background = cx.background_executor().clone();
        self.is_saving_settings = true;
        self.set_status("正在保存可信设备设置…", cx);
        cx.spawn(async move |shell, cx| {
            let result = background
                .spawn(async move {
                    session::change_trusted_device(session.as_ref(), &path, change).await
                })
                .await;
            let _ = shell.update(cx, |shell, cx| {
                shell.is_saving_settings = false;
                match result {
                    Ok(devices) => {
                        shell.settings.trusted_devices = devices;
                        shell.editing_trusted = None;
                        shell.set_status(
                            "可信设备设置已保存；信任仅允许该真实身份免输入本机密码",
                            cx,
                        );
                    }
                    Err(error) => shell.set_status(format!("可信设备设置未确认：{error}"), cx),
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn trusted_devices_card(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let enabled = self.can_save_settings && !self.is_saving_settings;
        let mut card =
            ui_components::card()
                .p(px(16.))
                .gap_3()
                .child(ui_components::section_header(
                    "✓",
                    "可信设备",
                    "仅手动保存的真实 NodeId 可免输入本机访问密码；信任是单向的",
                ));
        if self.settings.trusted_devices.is_empty() {
            card = card.child(div().child("暂无可信设备")).child(
                div()
                    .text_sm()
                    .child("只有你手动信任的设备才会出现在这里。"),
            );
        }
        for device in &self.settings.trusted_devices {
            let Ok(peer) = NodeId::from_hex(&device.node_id) else {
                continue;
            };
            let mut row = div()
                .flex()
                .flex_col()
                .gap_2()
                .child(device.display_name.clone())
                .child(format!(
                    "设备 ID：{}",
                    device.last_short_id.as_deref().unwrap_or("未记录")
                ))
                .child(format!(
                    "Node ID：{}…{}",
                    &device.node_id[..8],
                    &device.node_id[24..]
                ))
                .child(format!(
                    "信任时间：{} UTC",
                    trusted_devices::date(device.trusted_at)
                ))
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(
                            ui_components::secondary_button("复制完整 Node ID", true).on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _: &MouseUpEvent, _, cx| {
                                    cx.write_to_clipboard(ClipboardItem::new_string(peer.to_hex()))
                                }),
                            ),
                        )
                        .child(
                            ui_components::secondary_button("修改名称", enabled).on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                    if shell.is_saving_settings {
                                        return;
                                    }
                                    if let Some(device) = shell
                                        .settings
                                        .trusted_devices
                                        .iter()
                                        .find(|d| d.node_id == peer.to_hex())
                                    {
                                        Self::set_text_field(
                                            &shell.trusted_name,
                                            device.display_name.clone(),
                                            cx,
                                        );
                                    }
                                    shell.editing_trusted = Some(peer);
                                    cx.notify();
                                }),
                            ),
                        )
                        .child(
                            ui_components::secondary_button("取消信任", enabled).on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                    shell.change_trusted_device(
                                        session::TrustedDeviceChange::Revoke { peer },
                                        cx,
                                    )
                                }),
                            ),
                        ),
                );
            if self.editing_trusted == Some(peer) {
                row = row
                    .child(Self::text_field_frame(&self.trusted_name, window, cx))
                    .child(
                        ui_components::secondary_button("保存名称", enabled).on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                let display_name = shell.trusted_name.read(cx).content.to_string();
                                shell.change_trusted_device(
                                    session::TrustedDeviceChange::Rename { peer, display_name },
                                    cx,
                                );
                            }),
                        ),
                    );
            }
            card = card.child(row);
        }
        for (peer, state) in &self.peer_states {
            if let network_state::PeerLifecycle::Connected(auth) = state
                && self.can_trust_peer(*peer)
            {
                card = card.child(
                    div()
                        .flex()
                        .gap_2()
                        .child(format!(
                            "已通过密码认证：{}（{}）",
                            peer.short(),
                            auth.label()
                        ))
                        .child(self.trust_peer_button(*peer, cx)),
                );
            }
        }
        card
    }
    fn settings_home(&self, window: &Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .id("settings-home")
            .key_context("DesktopShell")
            .track_focus(&self.focus_handle)
            .overflow_y_scroll()
            .overflow_x_hidden()
            .bg(rgb(ui_theme::PAGE_BG))
            .flex()
            .flex_col()
            .gap_3()
            .p(px(20.))
            .text_color(rgb(ui_theme::TEXT))
            .child(
                div()
                    .h(px(56.))
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .child(Self::brand_identity(
                        "P2P File 设置",
                        "个性化设置你的使用体验",
                    ))
                    .child(
                        ui_components::secondary_button("返回主界面", true).on_mouse_up(
                            MouseButton::Left,
                            cx.listener(|shell, _: &MouseUpEvent, _, cx| {
                                shell.close_settings_home(cx)
                            }),
                        ),
                    ),
            )
            .child(self.remote_password_card(window, cx))
            .child(self.trusted_devices_card(window, cx))
            .child(self.background_card(cx))
            .child(self.notifications_card(cx))
            .child(self.auto_resume_card(cx))
            .child(self.file_limits_card(window, cx))
            .child(self.receive_space_card(window, cx))
            .child(self.advanced_network_card(window, cx))
    }

    fn auto_resume_card(&self, cx: &mut Context<Self>) -> gpui::Div {
        ui_components::card()
            .child(ui_components::section_header("↻", "断网自动恢复", "仅恢复本次运行中意外断网的任务"))
            .child("默认关闭。恢复前重新验证身份和双向权限；从首次断线起累计最多尝试 5 次、等待 5 分钟。主动暂停、重启、权限或设置变更后需要手动继续；对端也需要支持自动恢复协议。")
            .child(ui_components::secondary_button(if self.settings.auto_resume {"关闭自动恢复"} else {"开启自动恢复"}, self.can_save_settings && !self.is_saving_settings)
                .on_mouse_up(MouseButton::Left, cx.listener(|shell, _, _, cx| shell.toggle_auto_resume(cx))))
    }
    fn toggle_auto_resume(&mut self, cx: &mut Context<Self>) {
        if !self.can_save_settings || self.is_saving_settings {
            return;
        }
        let enabled = !self.settings.auto_resume;
        let config_file = self.config_file.clone();
        let background = cx.background_executor().clone();
        self.is_saving_settings = true;
        cx.spawn(async move |shell, cx| {
            let result = background
                .spawn(async move { DesktopConfig::save_auto_resume(&config_file, enabled) })
                .await;
            let _ = shell.update(cx, |shell, cx| {
                shell.is_saving_settings = false;
                match result {
                    Ok(()) => {
                        shell.settings.auto_resume = enabled;
                        if let Some(service) = &shell.transfer_service {
                            service.set_auto_resume(enabled);
                        }
                        shell.set_status(
                            if enabled {
                                "自动恢复已开启并保存"
                            } else {
                                "自动恢复已关闭，等待中的恢复已取消"
                            },
                            cx,
                        );
                    }
                    Err(error) => shell.set_status(format!("自动恢复偏好未保存：{error}"), cx),
                }
            });
        })
        .detach();
    }
    fn notifications_card(&self, cx: &mut Context<Self>) -> gpui::Div {
        ui_components::card()
            .child(ui_components::section_header(
                "◉",
                "系统通知",
                "后台传输完成、失败或中断时提醒",
            ))
            .child("默认关闭；通知只显示结果数量，点击查看任务。目录与短时间内的多项结果合并提醒。")
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child(self.notification_note.clone()),
            )
            .child(
                ui_components::secondary_button(
                    if self.settings.notifications {
                        "关闭系统通知"
                    } else {
                        "开启系统通知"
                    },
                    self.can_save_settings && !self.is_saving_settings,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(|shell, _, _, cx| shell.toggle_notifications(cx)),
                ),
            )
    }
    fn toggle_notifications(&mut self, cx: &mut Context<Self>) {
        if !self.can_save_settings || self.is_saving_settings {
            return;
        }
        let enabled = !self.settings.notifications;
        let config_file = self.config_file.clone();
        let background = cx.background_executor().clone();
        self.is_saving_settings = true;
        cx.spawn(async move |shell, cx| {
            let result = background
                .spawn(async move { DesktopConfig::save_notifications(&config_file, enabled) })
                .await;
            let _ = shell.update(cx, |shell, cx| {
                shell.is_saving_settings = false;
                match result {
                    Ok(()) => {
                        shell.settings.notifications = enabled;
                        shell.outcome_alerts.clear_pending();
                        shell.native_alerts.set_enabled(enabled);
                        shell.notification_note = if enabled {
                            "正在检查系统通知权限…"
                        } else {
                            "系统通知已关闭"
                        }
                        .into();
                        shell.set_status(
                            if enabled {
                                "通知偏好已保存；系统权限由操作系统控制"
                            } else {
                                "系统通知已关闭并保存"
                            },
                            cx,
                        );
                    }
                    Err(error) => shell.set_status(format!("通知偏好未保存：{error}"), cx),
                }
            });
        })
        .detach();
    }
    fn focus_notified_task(&mut self, id: task_model::TaskId, cx: &mut Context<Self>) {
        self.close_settings_home(cx);
        self.task_filter = Default::default();
        Self::set_text_field(&self.task_search, "", cx);
        if let Some(task) = self.task_snapshot.iter().find(|task| task.id == id)
            && let Some(group) = &task.group
        {
            self.expanded_groups.insert(group.clone());
        }
        let snapshot = ui_model::Snapshot {
            space: Default::default(),
            detail_selection: None,
            detail: None,
            tasks: self.task_snapshot.clone(),
            queue: queue::TaskQueue::default().metrics(),
            speeds: HashMap::new(),
        };
        self.task_rows = snapshot.list(&self.expanded_groups);
        if let Some(index) = self
            .task_rows
            .iter()
            .position(|row| matches!(row, ui_model::ListRow::Task(task) if task.id == id))
        {
            self.selected_task = Some(id);
            self.task_scroll
                .scroll_to_item(index, gpui::ScrollStrategy::Center);
            self.set_status("已定位通知对应的任务", cx);
        } else {
            self.set_status("通知对应的历史记录已移除", cx);
        }
    }

    fn receive_space_card(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        ui_components::card()
            .child(ui_components::section_header("▣", "接收磁盘空间", "同一文件系统的任务共享接收预算"))
            .child(ui_components::field_label("安全余量（MiB，默认 64，范围 0..4096）"))
            .child(Self::text_field_frame(&self.receive_safety_input, window, cx))
            .child(div().text_xs().text_color(rgb(ui_theme::TEXT_SECONDARY))
                .child("余量在每个文件系统只计算一次；修改后用于后续接收。预检查结合已验证的持久断点，不能保证运行期间空间充足。空间不足时保留断点，腾出空间后手动继续。"))
            .child(self.receive_space_status.clone())
            .child(ui_components::secondary_button("保存接收安全余量", self.can_save_settings && !self.is_saving_settings)
                .on_mouse_up(MouseButton::Left, cx.listener(|shell, _, _, cx| shell.apply_receive_space(cx))))
    }
    fn apply_receive_space(&mut self, cx: &mut Context<Self>) {
        if !self.can_save_settings || self.is_saving_settings {
            return;
        }
        let parsed = self
            .receive_safety_input
            .read(cx)
            .content
            .trim()
            .parse::<u16>();
        let value = match parsed {
            Ok(value) if space_budget::validate_safety_mib(value).is_ok() => value,
            _ => {
                self.set_status("接收安全余量必须为 0..4096 MiB 的整数", cx);
                return;
            }
        };
        let config_file = self.config_file.clone();
        let background = cx.background_executor().clone();
        self.is_saving_settings = true;
        cx.spawn(async move |shell, cx| {
            let result = background
                .spawn(async move { DesktopConfig::save_receive_safety_mib(&config_file, value) })
                .await;
            let _ = shell.update(cx, |shell, cx| {
                shell.is_saving_settings = false;
                match result {
                    Ok(()) => {
                        shell.settings.receive_safety_mib = value;
                        if let Some(service) = &shell.transfer_service {
                            let _ = service.receive_space.set_safety_mib(value);
                        }
                        shell.set_status("接收安全余量已保存，将用于后续接收", cx);
                    }
                    Err(error) => shell.set_status(format!("接收安全余量未保存：{error}"), cx),
                }
            });
        })
        .detach();
    }

    fn file_limits_card(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        ui_components::card()
            .child(ui_components::section_header("⇅", "文件传输限速", "各设备共享总额度；0 表示不限速"))
            .child(div().flex().gap_3()
                .child(div().flex_1().flex().flex_col().gap_2()
                    .child(ui_components::field_label("上传上限（KiB/s）"))
                    .child(Self::text_field_frame(&self.upload_limit_input, window, cx)))
                .child(div().flex_1().flex().flex_col().gap_2()
                    .child(ui_components::field_label("下载上限（KiB/s）"))
                    .child(Self::text_field_frame(&self.download_limit_input, window, cx))))
            .child(div().text_xs().text_color(rgb(ui_theme::TEXT_SECONDARY))
                .child("1 MiB/s = 1024 KiB/s。直连与 Relay 文件共用额度；隧道与测速独立。下载允许有限的在途缓冲。"))
            .child(ui_components::secondary_button("保存并应用限速", self.can_save_settings && !self.is_saving_settings)
                .on_mouse_up(MouseButton::Left, cx.listener(|shell, _, _, cx| shell.apply_file_limits(cx))))
    }
    fn apply_file_limits(&mut self, cx: &mut Context<Self>) {
        if !self.can_save_settings || self.is_saving_settings {
            return;
        }
        let limits = match bandwidth::FileLimits::parse(
            &self.upload_limit_input.read(cx).content,
            &self.download_limit_input.read(cx).content,
        ) {
            Ok(limits) => limits,
            Err(error) => {
                self.set_status(error, cx);
                return;
            }
        };
        let config_file = self.config_file.clone();
        let background = cx.background_executor().clone();
        self.is_saving_settings = true;
        cx.spawn(async move |shell, cx| {
            let result = background
                .spawn(async move { DesktopConfig::save_file_limits(&config_file, limits) })
                .await;
            let _ = shell.update(cx, |shell, cx| {
                shell.is_saving_settings = false;
                match result {
                    Ok(()) => {
                        shell.settings.file_limits = limits;
                        if let Some(service) = &shell.transfer_service {
                            let _ = service.set_file_limits(limits);
                        }
                        shell.set_status("文件限速已保存并应用到当前传输", cx);
                    }
                    Err(error) => shell.set_status(format!("文件限速未保存：{error}"), cx),
                }
            });
        })
        .detach();
    }

    fn connection_card(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let identity = self
            .local_short_id
            .map(|id| id.display())
            .unwrap_or_else(|| "等待信令分配设备 ID".to_owned());
        let connected = self.selected_peer(cx).is_some_and(|peer| {
            self.peer_states
                .get(&peer)
                .is_some_and(network_state::PeerLifecycle::outbound_authorized)
        });

        let local = div()
            .w_full()
            .flex()
            .items_center()
            .gap_2()
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child("本机 ID"),
            )
            .child(
                div()
                    .max_w(px(240.))
                    .min_w_0()
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_MUTED))
                    .cursor(if self.identity_id.is_some() {
                        CursorStyle::PointingHand
                    } else {
                        CursorStyle::Arrow
                    })
                    .hover(|style| style.bg(rgb(ui_theme::PRIMARY_SOFT)))
                    .rounded_sm()
                    .px(px(4.))
                    .truncate()
                    .child(identity)
                    .on_mouse_up(MouseButton::Left, cx.listener(Self::copy_short_id)),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(ui_theme::PRIMARY))
                    .cursor(if self.identity_id.is_some() {
                        CursorStyle::PointingHand
                    } else {
                        CursorStyle::Arrow
                    })
                    .hover(|style| style.bg(rgb(ui_theme::PRIMARY_SOFT)))
                    .rounded_sm()
                    .px(px(4.))
                    .child("复制")
                    .on_mouse_up(MouseButton::Left, cx.listener(Self::copy_short_id)),
            );

        let peer = div()
            .flex()
            .w_full()
            .items_center()
            .gap_2()
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .child(Self::text_field_frame(&self.peer_id, window, cx).rounded_lg()),
            )
            .child(self.connect_peer_button(cx));

        let fields = div()
            .flex()
            .flex_col()
            .gap_2()
            .child(local)
            .child(peer)
            .child(Self::text_field_frame(&self.peer_password, window, cx))
            .children(
                self.selected_peer(cx)
                    .filter(|peer| self.can_trust_peer(*peer))
                    .map(|peer| self.trust_peer_button(peer, cx)),
            );

        let mut speed_test_button = ui_components::compact_secondary_button("速度测试", connected);
        if connected {
            speed_test_button = speed_test_button
                .bg(rgb(ui_theme::PRIMARY_SOFT))
                .border_color(rgb(ui_theme::PRIMARY))
                .text_color(rgb(ui_theme::PRIMARY));
        }
        let speed_test_action = speed_test_button.on_mouse_up(
            MouseButton::Left,
            cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                if connected {
                    shell.toggle_speed_test_panel(cx);
                }
            }),
        );

        ui_components::card()
            .h(px(224.))
            .p(px(12.))
            .gap_2()
            .child(ui_components::section_header(
                "↔",
                "连接设备",
                "输入设备 ID；对端已信任本机时可免密码连接",
            ))
            .child(fields)
            .when(!self.local_password.read(cx).content.is_empty(), |card| {
                card.child(
                    div()
                        .text_xs()
                        .child("已生成本机密码：在设置中显示、复制并保存"),
                )
            })
            .child(
                div()
                    .w_full()
                    .flex()
                    .justify_start()
                    .child(speed_test_action),
            )
    }

    fn transfer_card(&mut self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let connected = self.selected_peer(cx).is_some_and(|peer| {
            self.peer_states
                .get(&peer)
                .is_some_and(network_state::PeerLifecycle::outbound_authorized)
        });
        let speed_running = self
            .speed_views
            .0
            .values()
            .any(|view| view.snapshot.status == speed::SpeedStatus::Running);
        let enabled = connected && !speed_running && self.transfer_service.is_some();
        let concurrency_selector = div()
            .flex()
            .items_center()
            .gap_1()
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT))
                    .child("并发："),
            )
            .child(Self::compact_text_field_frame(
                &self.concurrency_input,
                window,
                cx,
            ));

        let file_actions = div()
            .flex()
            .items_center()
            .gap_2()
            .child(
                ui_components::compact_secondary_button("选择文件", enabled)
                    .on_mouse_up(MouseButton::Left, cx.listener(Self::choose_files)),
            )
            .child(
                ui_components::compact_secondary_button("选择目录", enabled)
                    .on_mouse_up(MouseButton::Left, cx.listener(Self::choose_folder)),
            );
        let drop_hint = if self.drop_admission(cx).allowed() {
            "可拖入文件和目录 · 每批最多 128 项"
        } else {
            "连接并授权后可拖入文件和目录"
        };
        let transfer_toolbar = div()
            .flex()
            .items_center()
            .justify_between()
            .gap_3()
            .child(
                div().flex().flex_col().gap_1().child(file_actions).child(
                    div()
                        .text_xs()
                        .text_color(rgb(ui_theme::TEXT_MUTED))
                        .child(drop_hint),
                ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(concurrency_selector)
                    .child(
                        div()
                            .text_xs()
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .text_color(rgb(ui_theme::TEXT))
                            .child(format!(
                                "任务 {}/{}",
                                self.task_snapshot
                                    .iter()
                                    .filter(|t| self
                                        .task_filter
                                        .matches(t, &self.settings.trusted_devices))
                                    .count(),
                                self.task_snapshot.len()
                            )),
                    ),
            );

        let task_list = if self.task_rows.is_empty() {
            div()
                .flex_1()
                .min_h_0()
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .gap_2()
                .text_color(rgb(ui_theme::TEXT_SECONDARY))
                .child(
                    div()
                        .text_size(px(24.))
                        .text_color(rgb(ui_theme::TEXT_MUTED))
                        .child("▤"),
                )
                .child(
                    div()
                        .text_sm()
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .text_color(rgb(ui_theme::TEXT))
                        .child(if self.task_filter.active() {
                            "没有匹配的任务"
                        } else {
                            "暂无传输任务"
                        }),
                )
                .child(div().text_xs().child(if self.task_filter.active() {
                    "调整筛选条件或点击重置"
                } else {
                    "连接设备后选择文件或文件夹开始传输"
                }))
                .into_any_element()
        } else {
            gpui::uniform_list(
                "transfer-tasks",
                self.task_rows.len(),
                cx.processor(|shell, range: Range<usize>, _, cx| {
                    let end = range.end.min(shell.task_rows.len());
                    (range.start.min(end)..end)
                        .map(|index| shell.task_row(index, cx))
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(self.task_scroll.clone())
            .flex_1()
            .min_h_0()
            .into_any_element()
        };

        ui_components::card()
            .p(px(12.))
            .gap_2()
            .flex_1()
            .min_h_0()
            .flex_shrink()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .child(ui_components::section_header(
                        "▤",
                        "文件传输",
                        "选择文件或目录，在已认证设备之间传输",
                    ))
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(ui_theme::TEXT_SECONDARY))
                            .child(self.queue_status.clone()),
                    ),
            )
            .child(transfer_toolbar)
            .child(self.task_filter_toolbar(window, cx))
            .child(
                div()
                    .w_full()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .flex_col()
                    .overflow_hidden()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(ui_theme::BORDER))
                    .child(task_list),
            )
    }

    fn receive_directory_card(&self, cx: &Context<Self>) -> gpui::Div {
        let directory = self
            .settings
            .receive_directory
            .as_ref()
            .and_then(|path| path.to_str())
            .unwrap_or("尚未选择接收目录");
        let applied_differs = self.settings.receive_directory != self.applied_receive_root;
        let receive = div()
            .flex_1()
            .min_w_0()
            .flex()
            .items_center()
            .gap_2()
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .h(px(36.))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px(px(10.))
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(ui_theme::BORDER))
                    .bg(rgb(ui_theme::SURFACE_SUBTLE))
                    .child(div().text_color(rgb(ui_theme::PRIMARY)).child("▱"))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .text_sm()
                            .text_color(rgb(ui_theme::TEXT_SECONDARY))
                            .child(directory.to_owned()),
                    ),
            )
            .child(ui_components::secondary_button("更改", true).on_mouse_up(
                MouseButton::Left,
                cx.listener(Self::choose_receive_directory),
            ));
        ui_components::card()
            .h(px(184.))
            .p(px(12.))
            .gap_2()
            .child(ui_components::section_header(
                "▱",
                "接收目录",
                if applied_differs {
                    "目录更改待保存；保存后仅新任务生效（仅本机可见）"
                } else {
                    "接收文件默认保存在此处；目录更改仅新任务生效（仅本机可见）"
                },
            ))
            .child(receive)
    }

    fn connection_receive_row(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let connection = self.connection_card(window, cx);
        let receive_directory = self.receive_directory_card(cx);
        div()
            .flex()
            .gap_3()
            .child(div().flex_1().min_w_0().child(connection))
            .child(div().flex_1().min_w_0().child(receive_directory))
    }

    fn speed_test_card(&mut self, cx: &mut Context<Self>) -> gpui::Div {
        let running_view = self
            .displayed_speed()
            .filter(|(_, view)| view.snapshot.status == speed::SpeedStatus::Running);
        let running = running_view.is_some();
        let waiting = self.speed_request_until.is_some() && !running;
        let can_start = self.selected_peer(cx).is_some_and(|peer| {
            self.peer_states
                .get(&peer)
                .is_some_and(network_state::PeerLifecycle::outbound_authorized)
        }) && self.transfer_service.is_some()
            && !running
            && !waiting;
        let editing_enabled = !self.is_saving_settings;

        let direction_selector = div()
            .flex()
            .items_center()
            .rounded_md()
            .border_1()
            .border_color(rgb(ui_theme::BORDER))
            .overflow_hidden()
            .child(self.speed_direction_button("speed-both", "双向", SpeedtestDirection::Both, cx))
            .child(self.speed_direction_button(
                "speed-upload",
                "仅上传",
                SpeedtestDirection::Upload,
                cx,
            ))
            .child(self.speed_direction_button(
                "speed-download",
                "仅下载",
                SpeedtestDirection::Download,
                cx,
            ));
        let duration_label = match self.settings.speedtest_seconds {
            30 => "30 秒（最短）".to_owned(),
            seconds if seconds.is_multiple_of(60) => {
                format!("{} 分钟", seconds / 60)
            }
            seconds => format!("{seconds} 秒"),
        };
        let duration_button = div()
            .id("speed-duration-select")
            .h(px(36.))
            .w(px(152.))
            .px(px(10.))
            .flex()
            .items_center()
            .justify_between()
            .rounded_md()
            .border_1()
            .border_color(rgb(ui_theme::BORDER))
            .bg(rgb(ui_theme::SURFACE))
            .text_sm()
            .text_color(rgb(ui_theme::TEXT))
            .cursor(if editing_enabled {
                CursorStyle::PointingHand
            } else {
                CursorStyle::Arrow
            })
            .child(duration_label)
            .child("⌄")
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|shell, _: &MouseUpEvent, _, cx| shell.toggle_speed_duration_menu(cx)),
            );
        let duration_options = [
            (30, "30 秒（最短）"),
            (60, "1 分钟"),
            (120, "2 分钟"),
            (300, "5 分钟"),
            (600, "10 分钟"),
        ];
        let mut duration_menu = div()
            .absolute()
            .top(px(40.))
            .left(px(0.))
            .w(px(152.))
            .flex()
            .flex_col()
            .gap_1()
            .p(px(4.))
            .rounded_md()
            .border_1()
            .border_color(rgb(ui_theme::BORDER))
            .bg(rgb(ui_theme::SURFACE));
        for (seconds, label) in duration_options {
            let mut option = div()
                .id(("speed-duration", u32::from(seconds)))
                .h(px(32.))
                .px(px(8.))
                .flex()
                .items_center()
                .rounded_sm()
                .text_sm()
                .text_color(rgb(ui_theme::TEXT))
                .child(label);
            if self.settings.speedtest_seconds == seconds {
                option = option
                    .bg(rgb(ui_theme::PRIMARY_SOFT))
                    .text_color(rgb(ui_theme::PRIMARY));
            }
            duration_menu = duration_menu.child(option.on_mouse_up(
                MouseButton::Left,
                cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                    shell.set_speedtest_duration(seconds, cx)
                }),
            ));
        }
        let duration_selector = div()
            .relative()
            .child(duration_button)
            .when(self.show_speed_duration_menu, |selector| {
                selector.child(gpui::deferred(duration_menu).with_priority(10))
            });
        let controls = div()
            .flex()
            .items_center()
            .gap_2()
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(ui_theme::TEXT))
                    .child("方向"),
            )
            .child(direction_selector)
            .child(div().w(px(1.)).h(px(28.)).bg(rgb(ui_theme::BORDER)))
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(ui_theme::TEXT))
                    .child("时长"),
            )
            .child(duration_selector)
            .child(div().flex_1())
            .child(
                ui_components::primary_button(
                    if running {
                        "测速中…"
                    } else if waiting {
                        "等待授权…"
                    } else {
                        "开始测速"
                    },
                    can_start,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(|shell, _: &MouseUpEvent, _, cx| shell.start_speed_ui(cx)),
                ),
            )
            .when(running, |controls| {
                controls.child(ui_components::secondary_button("取消", true).on_mouse_up(
                    MouseButton::Left,
                    cx.listener(|shell, _: &MouseUpEvent, _, cx| shell.cancel_speed_ui(cx)),
                ))
            });

        let header = div()
            .w_full()
            .flex()
            .items_center()
            .justify_between()
            .child(ui_components::section_header(
                "◉",
                "速度测试",
                "测试与对端设备的直连网络性能，了解当前连接质量",
            ))
            .child(
                div()
                    .id("close-speed-test")
                    .w(px(28.))
                    .h(px(28.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .px(px(8.))
                    .text_size(px(18.))
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .rounded_md()
                    .cursor(CursorStyle::PointingHand)
                    .hover(|style| style.bg(rgb(ui_theme::SURFACE_SUBTLE)))
                    .child("×")
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|shell, _: &MouseUpEvent, _, cx| {
                            shell.toggle_speed_test_panel(cx)
                        }),
                    ),
            );
        let mut result = ui_components::card().child(header);
        result = result.child(controls);

        if let Some((peer, view)) = self.displayed_speed() {
            let snapshot = &view.snapshot;
            let sending = match snapshot.direction {
                protocol::SpeedDirection::Upload => self
                    .identity
                    .as_ref()
                    .is_some_and(|identity| identity.node_id() == snapshot.owner),
                protocol::SpeedDirection::Download => self
                    .identity
                    .as_ref()
                    .is_some_and(|identity| identity.node_id() != snapshot.owner),
            };
            let direction = self.settings.speedtest_direction.label();
            let status = match snapshot.status {
                speed::SpeedStatus::Running => "测速中",
                speed::SpeedStatus::Completed => "已完成",
                speed::SpeedStatus::Cancelled => "已取消",
                speed::SpeedStatus::Interrupted => "已中断",
            };
            let status_tone = match snapshot.status {
                speed::SpeedStatus::Running => ui_components::StatusTone::Info,
                speed::SpeedStatus::Completed => ui_components::StatusTone::Success,
                speed::SpeedStatus::Cancelled => ui_components::StatusTone::Warning,
                speed::SpeedStatus::Interrupted => ui_components::StatusTone::Danger,
            };
            let progress = (snapshot.elapsed.as_secs_f64() / f64::from(snapshot.seconds.max(1))
                * 100.)
                .min(100.);
            let rtt = if snapshot.rtt.is_zero() {
                "暂无样本".to_owned()
            } else {
                format!("{:.1} ms", snapshot.rtt.as_secs_f64() * 1_000.)
            };
            let actual_speed = if snapshot.status == speed::SpeedStatus::Running {
                view.instant
            } else {
                snapshot.bytes_per_second
            };
            let speed_result_available = matches!(
                snapshot.status,
                speed::SpeedStatus::Running | speed::SpeedStatus::Completed
            );
            let retained_upload = if self.settings.speedtest_direction == SpeedtestDirection::Both {
                self.speedtest_upload_result
                    .as_ref()
                    .filter(|upload| upload.status == speed::SpeedStatus::Completed)
            } else {
                None
            };
            let upload_speed = if sending && speed_result_available {
                format!("{:.2} MB/s", actual_speed / 1_000_000.)
            } else if let Some(upload) = retained_upload {
                format!("{:.2} MB/s", upload.bytes_per_second / 1_000_000.)
            } else if sending {
                "未完成".to_owned()
            } else {
                "未测试".to_owned()
            };
            let download_speed = if sending {
                "未测试".to_owned()
            } else if speed_result_available {
                format!("{:.2} MB/s", actual_speed / 1_000_000.)
            } else {
                "未完成".to_owned()
            };
            let result_description = match snapshot.status {
                speed::SpeedStatus::Running => "正在通过认证直连采集真实传输数据",
                speed::SpeedStatus::Completed
                    if self.settings.speedtest_direction == SpeedtestDirection::Both
                        && snapshot.direction == protocol::SpeedDirection::Upload =>
                {
                    "上传阶段完成，正在准备下载阶段"
                }
                speed::SpeedStatus::Completed
                    if self.settings.speedtest_direction == SpeedtestDirection::Both =>
                {
                    "双向测速已完成，结果来自本次直连传输"
                }
                speed::SpeedStatus::Completed => "测试已完成，结果来自本次直连传输",
                speed::SpeedStatus::Cancelled => "本次测速已取消",
                speed::SpeedStatus::Interrupted => "连接中断，本次测速未完成",
            };
            result = result
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_3()
                        .child(ui_components::status_badge(status, status_tone))
                        .child(
                            div()
                                .flex_1()
                                .text_xs()
                                .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                .child(format!(
                                    "{result_description} · 对端 {} · {direction}",
                                    peer.short()
                                )),
                        )
                        .when(running, |row| {
                            row.child(ui_components::progress_bar(progress)).child(
                                div()
                                    .w(px(42.))
                                    .text_xs()
                                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                    .child(format!("{progress:.0}%")),
                            )
                        }),
                )
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(ui_components::metric_tile(
                            "上传速度",
                            upload_speed,
                            if retained_upload.is_some() || sending && speed_result_available {
                                "本次测试"
                            } else if self.settings.speedtest_direction == SpeedtestDirection::Both
                            {
                                "等待上传阶段"
                            } else {
                                "选择仅上传后测试"
                            },
                            ui_theme::SUCCESS_SOFT,
                        ))
                        .child(ui_components::metric_tile(
                            "下载速度",
                            download_speed,
                            if sending {
                                if self.settings.speedtest_direction == SpeedtestDirection::Both {
                                    "等待下载阶段"
                                } else {
                                    "选择仅下载后测试"
                                }
                            } else {
                                "本次测试"
                            },
                            ui_theme::PRIMARY_SOFT,
                        ))
                        .child(ui_components::metric_tile(
                            "延迟",
                            rtt,
                            "直连往返时延",
                            ui_theme::SURFACE_SUBTLE,
                        )),
                )
                .child(
                    div()
                        .w_full()
                        .px(px(12.))
                        .py(px(8.))
                        .rounded_md()
                        .bg(rgb(ui_theme::SURFACE_SUBTLE))
                        .text_xs()
                        .text_color(rgb(ui_theme::TEXT_SECONDARY))
                        .child(format!(
                            "{} · 实际传输 {} · 耗时 {:.1} 秒",
                            if snapshot.rtt.is_zero() {
                                "连接质量数据尚不足"
                            } else {
                                "直连质量测试完成"
                            },
                            format_bytes(snapshot.bytes),
                            snapshot.elapsed.as_secs_f64()
                        )),
                );
        } else if waiting {
            result = result.child(
                div()
                    .p(px(12.))
                    .rounded_md()
                    .bg(rgb(ui_theme::WARNING_SOFT))
                    .text_sm()
                    .text_color(rgb(ui_theme::WARNING))
                    .child("等待对端确认；文件传输活动期间无法测速，不会自动暂停任务"),
            );
        } else {
            result = result.child(
                div()
                    .p(px(12.))
                    .rounded_md()
                    .bg(rgb(ui_theme::SURFACE_SUBTLE))
                    .text_sm()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child(format!(
                        "尚未测速 · 当前方向：{} · 使用认证直连，不读取或生成本地文件",
                        self.settings.speedtest_direction.label()
                    )),
            );
        }
        result
    }

    fn port_forward_settings(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let editing_allowed = self.editing_allowed_id.is_some();
        let mut allowed_rows = div()
            .h(px(150.))
            .id("allowed-forward-targets")
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_1();
        if self.settings.allowed_forward_targets.is_empty() {
            allowed_rows = allowed_rows.child(
                div()
                    .py(px(10.))
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child("还没有允许远端访问的服务"),
            );
        }
        for entry in &self.settings.allowed_forward_targets {
            let id = entry.id.clone();
            let edit_id = id.clone();
            let delete_id = id.clone();
            let enabled = entry.enabled;
            let mut row = div()
                .w_full()
                .flex()
                .items_center()
                .gap_2()
                .px(px(8.))
                .py(px(6.))
                .rounded_md()
                .bg(rgb(ui_theme::SURFACE_SUBTLE))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(
                            div()
                                .text_sm()
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .text_color(rgb(ui_theme::TEXT))
                                .truncate()
                                .child(entry.name.clone()),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                .child(format!(
                                    "{} · 授权 {} 台设备{}",
                                    entry.target,
                                    entry.allowed_peers.len(),
                                    if entry.allowed_peers.is_empty() {
                                        "（拒绝所有 peer）"
                                    } else {
                                        ""
                                    }
                                )),
                        ),
                )
                .child(
                    div()
                        .w(px(48.))
                        .text_xs()
                        .text_color(rgb(if enabled {
                            ui_theme::SUCCESS
                        } else {
                            ui_theme::TEXT_SECONDARY
                        }))
                        .child(if enabled { "已启用" } else { "已停用" }),
                );
            row = row
                .child(
                    ui_components::secondary_button(
                        if enabled { "停用" } else { "启用" },
                        !self.is_saving_settings,
                    )
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                            shell.toggle_allowed_target(id.clone(), cx)
                        }),
                    ),
                )
                .child(
                    ui_components::secondary_button("编辑", !self.is_saving_settings).on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                            shell.edit_allowed_target(edit_id.clone(), cx)
                        }),
                    ),
                )
                .child(
                    ui_components::secondary_button("删除", !self.is_saving_settings).on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                            shell.delete_allowed_target(delete_id.clone(), cx)
                        }),
                    ),
                );
            if self.is_saving_settings {
                row = row.opacity(0.55);
            }
            allowed_rows = allowed_rows.child(row);
        }

        let allowed_actions = div()
            .flex()
            .items_center()
            .gap_2()
            .child(
                ui_components::primary_button(
                    if editing_allowed {
                        "保存服务到列表"
                    } else {
                        "+ 添加允许服务"
                    },
                    !self.is_saving_settings,
                )
                .on_mouse_up(MouseButton::Left, cx.listener(Self::save_allowed_target)),
            )
            .when(editing_allowed, |row| {
                row.child(
                    ui_components::secondary_button("取消编辑", !self.is_saving_settings)
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(|shell, _: &MouseUpEvent, _, cx| {
                                shell.cancel_allowed_edit(cx)
                            }),
                        ),
                )
            });

        let mut tunnel_rows = div()
            .h(px(220.))
            .id("local-tunnel-rules")
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_1();
        if self.settings.tunnel_rules.is_empty() {
            tunnel_rows = tunnel_rows.child(
                div()
                    .py(px(10.))
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child("还没有本机转发规则"),
            );
        }
        for rule in &self.settings.tunnel_rules {
            let id = rule.id.clone();
            let enable_id = id.clone();
            let auto_id = id.clone();
            let edit_id = id.clone();
            let delete_id = id.clone();
            let runtime = self
                .tunnel_states
                .get(&id)
                .cloned()
                .unwrap_or(session::TunnelRuntimeState::Stopped);
            let running = matches!(
                runtime,
                session::TunnelRuntimeState::WaitingAuthorization
                    | session::TunnelRuntimeState::Starting
                    | session::TunnelRuntimeState::Running
            );
            let (runtime_label, runtime_color) = match &runtime {
                session::TunnelRuntimeState::WaitingAuthorization => {
                    ("等待输入对端密码 / 授权", ui_theme::WARNING)
                }
                session::TunnelRuntimeState::Starting => ("等待认证连接", ui_theme::WARNING),
                session::TunnelRuntimeState::Running => ("运行中", ui_theme::SUCCESS),
                session::TunnelRuntimeState::Stopped => ("已停止", ui_theme::TEXT_SECONDARY),
                session::TunnelRuntimeState::Error(_) => ("错误", ui_theme::DANGER),
            };
            let peer_label = NodeId::from_hex(&rule.peer_node_id)
                .map(|peer| peer.short())
                .unwrap_or_else(|_| rule.peer_node_id.clone());
            let mut row = div()
                .w_full()
                .flex()
                .flex_col()
                .gap_2()
                .p(px(9.))
                .rounded_md()
                .bg(rgb(ui_theme::SURFACE_SUBTLE))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_2()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .text_sm()
                                .font_weight(gpui::FontWeight::MEDIUM)
                                .text_color(rgb(ui_theme::TEXT))
                                .truncate()
                                .child(rule.name.clone()),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(rgb(runtime_color))
                                .child(runtime_label),
                        ),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(rgb(ui_theme::TEXT_SECONDARY))
                        .child(format!(
                            "本机 {}  →  设备 {}  →  {}",
                            rule.listen, peer_label, rule.target
                        )),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(
                            ui_components::primary_button(
                                if running {
                                    "停止"
                                } else if matches!(runtime, session::TunnelRuntimeState::Error(_)) {
                                    "重新启动"
                                } else {
                                    "启动"
                                },
                                !self.is_saving_settings && (running || rule.enabled),
                            )
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                    shell.toggle_tunnel_runtime(id.clone(), cx)
                                }),
                            ),
                        )
                        .child(
                            ui_components::secondary_button(
                                if rule.enabled { "停用" } else { "启用" },
                                !self.is_saving_settings,
                            )
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                    shell.toggle_tunnel_enabled(enable_id.clone(), cx)
                                }),
                            ),
                        )
                        .child(
                            ui_components::secondary_button(
                                if rule.auto_start {
                                    "关闭自动启动"
                                } else {
                                    "自动启动"
                                },
                                !self.is_saving_settings,
                            )
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                    shell.toggle_tunnel_auto_start(auto_id.clone(), cx)
                                }),
                            ),
                        )
                        .child(
                            ui_components::secondary_button("编辑", !self.is_saving_settings)
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                        shell.edit_tunnel_rule(edit_id.clone(), cx)
                                    }),
                                ),
                        )
                        .child(
                            ui_components::secondary_button("删除", !self.is_saving_settings)
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                        shell.delete_tunnel_rule(delete_id.clone(), cx)
                                    }),
                                ),
                        ),
                );
            if let Some(detail) = self.tunnel_last_errors.get(&rule.id) {
                row = row.child(
                    div()
                        .text_xs()
                        .text_color(rgb(ui_theme::DANGER))
                        .child(format!("最近错误：{detail}")),
                );
            }
            tunnel_rows = tunnel_rows.child(row);
        }

        let editing_tunnel = self.editing_tunnel_id.is_some();
        div()
            .flex()
            .flex_col()
            .gap_3()
            .border_t_1()
            .border_color(rgb(ui_theme::BORDER))
            .pt(px(12.))
            .child(ui_components::section_header(
                "↔",
                "端口转发",
                "通过已认证的 P2P 连接访问另一台设备上的 TCP 服务",
            ))
            .child(ui_components::field_label("允许远端访问的服务"))
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(ui_theme::WARNING))
                    .child("仅明确授权的设备可通过本机访问此目标；空设备列表拒绝所有 peer。停用/删除立即撤销新连接权限。"),
            )
            .child(allowed_rows)
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(ui_components::field_label("名称"))
                            .child(Self::text_field_frame(&self.allowed_name, window, cx)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(ui_components::field_label("目标 IP:端口"))
                            .child(Self::text_field_frame(&self.allowed_target, window, cx)),
                    ),
            )
            .child(div().flex().flex_col().gap_1()
                .child(ui_components::field_label("授权设备完整 Node ID（逗号分隔）"))
                .child(Self::text_field_frame(&self.allowed_peers, window, cx)))
            .child(allowed_actions)
            .child(ui_components::field_label("本机转发规则"))
            .child(tunnel_rows)
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        div()
                            .w(px(170.))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(ui_components::field_label("名称"))
                            .child(Self::text_field_frame(&self.tunnel_name, window, cx)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(220.))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(ui_components::field_label("对端设备 ID"))
                            .child(Self::text_field_frame(&self.tunnel_peer, window, cx)),
                    )
                    .child(
                        div()
                            .w(px(160.))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(ui_components::field_label("本机监听地址"))
                            .child(Self::text_field_frame(&self.tunnel_listen, window, cx)),
                    )
                    .child(
                        div()
                            .w(px(180.))
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(ui_components::field_label("远端目标 IP:端口"))
                            .child(Self::text_field_frame(&self.tunnel_target, window, cx)),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        ui_components::primary_button(
                            if editing_tunnel {
                                "保存规则到列表"
                            } else {
                                "+ 添加转发规则"
                            },
                            !self.is_saving_settings,
                        )
                        .on_mouse_up(MouseButton::Left, cx.listener(Self::save_tunnel_rule)),
                    )
                    .when(editing_tunnel, |row| {
                        row.child(
                            ui_components::secondary_button("取消编辑", !self.is_saving_settings)
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(|shell, _: &MouseUpEvent, _, cx| {
                                        shell.cancel_tunnel_edit(cx)
                                    }),
                                ),
                        )
                    }),
            )
    }

    fn advanced_network_card(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let host = self.signal_host.read(cx).content.to_string();
        let port = self.signal_port.read(cx).content.to_string();
        let summary = if host.trim().is_empty() || port.trim().is_empty() {
            "尚未配置完整信令地址".to_owned()
        } else {
            format!(
                "{}:{} · {}",
                host.trim(),
                port.trim(),
                if self.settings.signal_tls.is_some() {
                    "TLS（已保存）"
                } else {
                    "明文 TCP（已保存）"
                }
            )
        };
        let toggle = ui_components::secondary_button(
            if self.show_settings {
                "收起"
            } else {
                "编辑"
            },
            true,
        )
        .on_mouse_up(
            MouseButton::Left,
            cx.listener(|shell, _: &MouseUpEvent, window, cx| shell.toggle_settings(window, cx)),
        );
        let mut card = ui_components::card().child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap_2()
                .child(ui_components::section_header(
                    "⋯",
                    "高级网络设置",
                    "信令连接参数与当前状态",
                ))
                .child(toggle),
        );

        if self.show_settings {
            card = card
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .text_xs()
                        .child(format!(
                            "真实设备身份（Node ID）：{}",
                            self.identity_id.as_deref().unwrap_or("身份不可用")
                        ))
                        .child(
                            ui_components::secondary_button(
                                "复制真实 Node ID",
                                self.identity_id.is_some(),
                            )
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(|shell, _, _, cx| {
                                    if let Some(identity) = &shell.identity_id {
                                        cx.write_to_clipboard(ClipboardItem::new_string(
                                            identity.clone(),
                                        ));
                                        shell.set_status(
                                            "已复制真实 Node ID；转发授权按此身份绑定",
                                            cx,
                                        );
                                    }
                                }),
                            ),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .gap_3()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .flex()
                                .flex_col()
                                .gap_2()
                                .child(ui_components::field_label("信令主机/IP"))
                                .child(Self::text_field_frame(&self.signal_host, window, cx)),
                        )
                        .child(
                            div()
                                .w(px(128.))
                                .flex()
                                .flex_col()
                                .gap_2()
                                .child(ui_components::field_label("端口"))
                                .child(Self::text_field_frame(&self.signal_port, window, cx)),
                        ),
                )
                .child(ui_components::secondary_button(if self.signal_tls_enabled { "信令 TLS：开（保存后应用）" } else { "信令 TLS：关，明文 TCP（保存后应用）" }, !self.is_saving_settings)
                    .on_mouse_up(MouseButton::Left, cx.listener(|shell, _, _, cx| { if !shell.is_saving_settings { shell.signal_tls_enabled = !shell.signal_tls_enabled; cx.notify(); } })))
                .when(self.signal_tls_enabled, |card| card
                    .child(ui_components::field_label("信令 CA 文件（可选，PEM 绝对路径）"))
                    .child(Self::text_field_frame(&self.signal_ca_file, window, cx))
                    .child(ui_components::field_label("证书校验主机名（可选）"))
                    .child(Self::text_field_frame(&self.signal_server_name, window, cx)))
                .child("TLS 开启时验证证书与主机名；校验失败停止连接，不降级为明文。关闭则使用兼容的明文 TCP。")
                .child(ui_components::field_label(
                    "Relay Server（可选，HOST:UDP_PORT）",
                ))
                .child(Self::text_field_frame(&self.relay_server, window, cx))
                .child("留空仅直连；配置后直连优先，失败时延迟尝试加密 UDP Relay")
                .child(self.port_forward_settings(window, cx))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .text_xs()
                                .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                .child(self.config_note.clone())
                                .child(self.identity_status.clone()),
                        )
                        .child(self.save_settings_button(cx)),
                );
        } else {
            card = card.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .text_sm()
                            .text_color(rgb(ui_theme::TEXT))
                            .child(summary),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(ui_theme::TEXT_SECONDARY))
                            .child(self.network_status.clone()),
                    ),
            );
        }
        card = card.child(
            div()
                .text_xs()
                .text_color(rgb(ui_theme::TEXT_SECONDARY))
                .child(self.network_path_status.clone()),
        );
        for (_, detail) in self.peer_path_status.values() {
            card = card.child(
                div()
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child(detail.clone()),
            );
        }
        card
    }
}

impl Focusable for DesktopShell {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for DesktopShell {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.show_settings_home {
            return self.settings_home(window, cx).into_any_element();
        }
        let speed_card = self.show_speed_test_panel.then(|| self.speed_test_card(cx));
        let drop_enabled = self.drop_admission(cx).allowed();

        div()
            .size_full()
            .id("desktop-shell")
            .can_drop(move |value, _, _| {
                drop_enabled
                    && value
                        .downcast_ref::<gpui::ExternalPaths>()
                        .is_some_and(|paths| drop_send::validate_paths(paths.paths()).is_ok())
            })
            .on_drop(cx.listener(Self::drop_paths))
            .when(drop_enabled, |page| {
                page.drag_over::<gpui::ExternalPaths>(|style, _, _, _| {
                    style.bg(rgb(ui_theme::PRIMARY_SOFT))
                })
            })
            .key_context("DesktopShell")
            .track_focus(&self.focus_handle)
            .overflow_y_scroll()
            .overflow_x_hidden()
            .bg(rgb(ui_theme::PAGE_BG))
            .flex()
            .flex_col()
            .gap_3()
            .p(px(20.))
            .text_color(rgb(ui_theme::TEXT))
            .on_action(cx.listener(|shell, _: &NextTask, _, cx| shell.select_task(false, cx)))
            .on_action(cx.listener(|shell, _: &PreviousTask, _, cx| shell.select_task(true, cx)))
            .on_action(cx.listener(|shell, _: &ExpandGroups, _, cx| shell.expand_groups(cx)))
            .on_action(cx.listener(|shell, _: &ChooseReceiveDirectory, _, cx| {
                shell.pick_receive_directory(cx)
            }))
            .on_action(cx.listener(|shell, _: &CycleDirection, _, cx| shell.change_direction(cx)))
            .on_action(cx.listener(|shell, _: &CycleDuration, _, cx| shell.change_duration(cx)))
            .on_action(
                cx.listener(|shell, _: &CycleConcurrency, _, cx| shell.change_concurrency(cx)),
            )
            .on_action(
                cx.listener(|shell, _: &NextField, window, cx| {
                    shell.focus_field(false, window, cx)
                }),
            )
            .on_action(cx.listener(|shell, _: &PreviousField, window, cx| {
                shell.focus_field(true, window, cx)
            }))
            .on_action(cx.listener(|shell, _: &CopyIdentity, _, cx| {
                if let Some(identity) = &shell.identity_id {
                    cx.write_to_clipboard(ClipboardItem::new_string(identity.clone()));
                    shell.set_status("已复制完整本机 ID", cx);
                }
            }))
            .on_action(cx.listener(|shell, _: &ConnectPeer, _, cx| shell.connect_current_peer(cx)))
            .on_action(cx.listener(|shell, _: &ChooseFiles, _, cx| shell.pick_files(cx)))
            .on_action(cx.listener(|shell, _: &ChooseFolder, _, cx| shell.pick_folder(cx)))
            .on_action(cx.listener(|shell, _: &SaveSettings, _, cx| shell.persist_settings(cx)))
            .on_action(cx.listener(|shell, _: &StartSpeed, _, cx| shell.start_speed_ui(cx)))
            .on_action(cx.listener(|shell, _: &CancelSpeed, _, cx| shell.cancel_speed_ui(cx)))
            .on_action(
                cx.listener(|shell, _: &ToggleSettings, _, cx| shell.toggle_settings_home(cx)),
            )
            .on_action(
                cx.listener(|shell, _: &PauseSelected, _, cx| shell.selected_action(false, cx)),
            )
            .on_action(
                cx.listener(|shell, _: &ResumeSelected, _, cx| shell.selected_action(true, cx)),
            )
            .child(self.app_header(cx))
            .when(self.show_diagnostics, |page| {
                page.child(self.diagnostics_card(cx))
            })
            .child(self.connection_receive_row(window, cx))
            .when_some(speed_card, |page, speed_card| page.child(speed_card))
            .child(self.transfer_card(window, cx).when(
                self.show_diagnostics || self.detail_selection.is_some(),
                |card| card.min_h(px(320.)).flex_shrink_0(),
            ))
            .when(self.detail_selection.is_some(), |page| {
                page.child(self.task_details_card(cx))
            })
            .child(
                div()
                    .w_full()
                    .p(px(10.))
                    .rounded_md()
                    .bg(rgb(ui_theme::PRIMARY_SOFT))
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child(self.status.clone()),
            )
            .into_any_element()
    }
}

/// Start the native GPUI application.
pub fn run(background_start: bool) {
    let startup = match DesktopStartup::load() {
        Ok(startup) => startup,
        Err(error) => {
            eprintln!("桌面启动失败：{error}");
            return;
        }
    };

    let application = Application::new();
    application.on_reopen(background::reopen);
    application.run(move |cx: &mut App| {
        cx.bind_keys([
            KeyBinding::new("backspace", Backspace, None),
            KeyBinding::new("delete", Delete, None),
            KeyBinding::new("left", Left, None),
            KeyBinding::new("right", Right, None),
            KeyBinding::new("shift-left", SelectLeft, None),
            KeyBinding::new("shift-right", SelectRight, None),
            KeyBinding::new("secondary-a", SelectAll, None),
            KeyBinding::new("secondary-v", Paste, None),
            KeyBinding::new("secondary-c", Copy, None),
            KeyBinding::new("secondary-x", Cut, None),
            KeyBinding::new("home", Home, None),
            KeyBinding::new("end", End, None),
            KeyBinding::new("ctrl-cmd-space", ShowCharacterPalette, None),
            KeyBinding::new("secondary-q", Quit, None),
            KeyBinding::new("secondary-down", NextTask, Some("DesktopShell")),
            KeyBinding::new("secondary-up", PreviousTask, Some("DesktopShell")),
            KeyBinding::new("secondary-e", ExpandGroups, Some("DesktopShell")),
            KeyBinding::new(
                "secondary-shift-d",
                ChooseReceiveDirectory,
                Some("DesktopShell"),
            ),
            KeyBinding::new("secondary-d", CycleDirection, Some("DesktopShell")),
            KeyBinding::new("secondary-l", CycleDuration, Some("DesktopShell")),
            KeyBinding::new("secondary-n", CycleConcurrency, Some("DesktopShell")),
            KeyBinding::new("tab", NextField, Some("DesktopShell")),
            KeyBinding::new("shift-tab", PreviousField, Some("DesktopShell")),
            KeyBinding::new("secondary-shift-c", CopyIdentity, Some("DesktopShell")),
            KeyBinding::new("secondary-enter", ConnectPeer, Some("DesktopShell")),
            KeyBinding::new("secondary-o", ChooseFiles, Some("DesktopShell")),
            KeyBinding::new("secondary-shift-o", ChooseFolder, Some("DesktopShell")),
            KeyBinding::new("secondary-s", SaveSettings, Some("DesktopShell")),
            KeyBinding::new("secondary-,", ToggleSettings, Some("DesktopShell")),
            KeyBinding::new("secondary-t", StartSpeed, Some("DesktopShell")),
            KeyBinding::new("secondary-shift-t", CancelSpeed, Some("DesktopShell")),
            KeyBinding::new("secondary-p", PauseSelected, Some("DesktopShell")),
            KeyBinding::new("secondary-r", ResumeSelected, Some("DesktopShell")),
        ]);

        let bounds = Bounds::centered(None, size(px(1180.), px(780.)), cx);
        let DesktopStartup {
            instance_lock,
            task_store,
            task_store_status,
            identity_id,
            identity,
            identity_status,
            config_file,
            settings,
            config_note,
            can_save_settings,
            has_saved_network_config,
            initial_password,
        } = startup;
        let initial_status = if task_store.is_none() || !task_store_status.contains("已就绪") {
            task_store_status.clone()
        } else if identity_id.is_some() {
            if settings.signal_host.is_empty() {
                "未配置有效信令；请保存设置后上线".to_owned()
            } else {
                "信令设置已保存；正在启动会话".to_owned()
            }
        } else {
            identity_status.clone()
        };
        let transfer_service = task_store.map(|store| {
            let service = transfer::TransferService::new(
                store,
                settings.receive_directory.clone().unwrap_or_default(),
            );
            // Settings were already validated (or replaced with safe defaults).
            service
                .set_send_limit(settings.send_concurrency)
                .expect("validated concurrency");
            service
        });
        if let Some(service) = &transfer_service {
            service
                .set_file_limits(settings.file_limits)
                .expect("validated file limits");
            service.set_auto_resume(settings.auto_resume);
            service
                .receive_space
                .set_safety_mib(settings.receive_safety_mib)
                .expect("validated receive margin");
        }
        let initial_file_limits = settings.file_limits;
        let initial_receive_safety = settings.receive_safety_mib;
        let initial_notifications = settings.notifications;
        let initial_receive_root = settings.receive_directory.clone();
        let initial_concurrency = settings.send_concurrency;
        let initial_host = settings.signal_host.clone();
        let initial_signal_tls = settings.signal_tls.clone();
        let initial_tls_enabled = initial_signal_tls.is_some();
        let initial_port = settings.signal_port.clone();
        let initial_relay = settings.relay_server.clone().unwrap_or_default();
        let startup_session_config = if has_saved_network_config && identity.is_some() {
            let mut config = session::DesktopSessionConfig::new(signal_server_spec(
                &settings.signal_host,
                &settings.signal_port,
            ));
            config.signal_tls = settings.signal_tls.clone();
            config.network.relay_server = settings.relay_server.clone();
            Some(config)
        } else {
            None
        };
        let initial_network_status = if has_saved_network_config {
            "正在准备长期在线网络会话".to_owned()
        } else if identity_id.is_some() {
            network_state::NetworkLifecycle::Unconfigured.label()
        } else {
            "本机身份不可用；网络会话未启动".to_owned()
        };
        let show_initial_password = initial_password.is_some();
        let start_hidden = background_start
            && settings.background.launch_at_login
            && has_saved_network_config
            && !show_initial_password;
        let window = cx.open_window(
            WindowOptions {
                show: !start_hidden,
                focus: !start_hidden,
                titlebar: Some(gpui::TitlebarOptions {
                    title: Some("P2P File".into()),
                    ..Default::default()
                }),
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(760.), px(560.))),
                app_id: Some("p2p-file".into()),
                ..Default::default()
            },
            move |_, cx| {
                let peer_id = cx.new(|cx| TextField::new(cx, "输入 9 位对方 ID"));
                let peer_password = cx
                    .new(|cx| TextField::new_password(cx, "对方访问密码；对端已信任本机时可留空"));
                let local_password = cx.new(|cx| {
                    let mut field = TextField::new_password(cx, "已设置；输入 6～12 位新密码");
                    if let Some(password) = initial_password {
                        field.content = password.expose().to_owned().into();
                        field.revealed = true;
                        field.selected_range = field.content.len()..field.content.len();
                    }
                    field
                });
                let concurrency_input =
                    cx.new(|cx| TextField::new_concurrency_value(cx, initial_concurrency));
                let upload_limit_input = cx.new(|cx| {
                    let mut field = TextField::new(cx, "0 表示不限速");
                    field.content = initial_file_limits.upload_kib.to_string().into();
                    field
                });
                let receive_safety_input = cx.new(|cx| {
                    let mut field = TextField::new(cx, "0..4096 MiB");
                    field.content = initial_receive_safety.to_string().into();
                    field
                });
                let download_limit_input = cx.new(|cx| {
                    let mut field = TextField::new(cx, "0 表示不限速");
                    field.content = initial_file_limits.download_kib.to_string().into();
                    field
                });
                let signal_host = cx.new(|cx| {
                    let mut field = TextField::new(cx, "输入 IPv4、IPv6 或主机名");
                    field.content = initial_host.into();
                    field
                });
                let signal_port = cx.new(|cx| {
                    let mut field = TextField::new(cx, "1–65535");
                    field.content = initial_port.into();
                    field
                });
                let signal_ca_file = cx.new(|cx| {
                    let mut field = TextField::new(cx, "留空使用内置 CA，或填写 PEM CA 的绝对路径");
                    field.content = initial_signal_tls
                        .as_ref()
                        .and_then(|tls| tls.ca_file.as_ref())
                        .and_then(|p| p.to_str())
                        .unwrap_or("")
                        .to_owned()
                        .into();
                    field
                });
                let signal_server_name = cx.new(|cx| {
                    let mut field =
                        TextField::new(cx, "留空按信令主机校验；可填写证书 DNS 名或 IP");
                    field.content = initial_signal_tls
                        .as_ref()
                        .and_then(|tls| tls.server_name.clone())
                        .unwrap_or_default()
                        .into();
                    field
                });
                let relay_server = cx.new(|cx| {
                    let mut field = TextField::new(cx, "留空或 relay.example:7001 / [IPv6]:7001");
                    field.content = initial_relay.into();
                    field
                });
                let allowed_name = cx.new(|cx| TextField::new(cx, "例如：SSH"));
                let allowed_target = cx.new(|cx| TextField::new(cx, "127.0.0.1:22"));
                let allowed_peers =
                    cx.new(|cx| TextField::new(cx, "明确授权的设备 ID，空列表拒绝所有设备"));
                let tunnel_name = cx.new(|cx| TextField::new(cx, "例如：家里 SSH"));
                let tunnel_peer = cx.new(|cx| TextField::new(cx, "完整的对端 Node ID"));
                let tunnel_listen = cx.new(|cx| {
                    let mut field = TextField::new(cx, "127.0.0.1:2222");
                    field.content = "127.0.0.1:2222".into();
                    field
                });
                let trusted_name = cx.new(|cx| TextField::new(cx, "本地设备备注"));
                let tunnel_target = cx.new(|cx| TextField::new(cx, "127.0.0.1:22"));
                let task_search = cx.new(|cx| TextField::new(cx, "搜索文件名或设备备注 / ID"));
                cx.new(|cx| {
                    cx.observe(
                        &task_search,
                        |shell: &mut DesktopShell,
                         input: Entity<TextField>,
                         cx: &mut Context<DesktopShell>| {
                            shell.task_filter.query = input.read(cx).content.to_string();
                            shell.refresh_task_rows(cx);
                        },
                    )
                    .detach();
                    cx.observe(
                        &concurrency_input,
                        |shell: &mut DesktopShell,
                         input: Entity<TextField>,
                         cx: &mut Context<DesktopShell>| {
                            if let Ok(value) = input.read(cx).content.to_string().parse::<u8>()
                                && (1..=3).contains(&value)
                            {
                                shell.set_send_concurrency(value, cx);
                            }
                        },
                    )
                    .detach();
                    DesktopShell {
                        peer_id,
                        peer_password,
                        local_password,
                        trusted_name,
                        editing_trusted: None,
                        local_short_id: None,
                        resolved_peer: None,
                        concurrency_input,
                        upload_limit_input,
                        download_limit_input,
                        receive_safety_input,
                        signal_host,
                        signal_port,
                        signal_tls_enabled: initial_tls_enabled,
                        signal_ca_file,
                        signal_server_name,
                        relay_server,
                        allowed_name,
                        allowed_target,
                        allowed_peers,
                        pending_tunnel_changes: std::collections::HashSet::new(),
                        tunnel_name,
                        tunnel_peer,
                        tunnel_listen,
                        tunnel_target,
                        editing_allowed_id: None,
                        editing_tunnel_id: None,
                        selected_files: Vec::new(),
                        native_dialogs: 0,
                        selected_folder: None,
                        settings,
                        identity_id,
                        identity,
                        identity_status: identity_status.into(),
                        config_file,
                        config_note: config_note.into(),
                        can_save_settings,
                        is_saving_settings: false,
                        _instance_lock: instance_lock,
                        transfer_service,
                        network_session: None,
                        network_status: initial_network_status.into(),
                        signal_state: if has_saved_network_config {
                            background::SignalState::Connecting
                        } else {
                            background::SignalState::Offline
                        },
                        background_files: (0, 0, 0),
                        network_path_status: "UDP 地址族尚未准备".into(),
                        peer_path_status: HashMap::new(),
                        connection_diagnostics: diagnostics::Diagnostics::new(Instant::now()),
                        show_diagnostics: false,
                        exporting_diagnostics: false,
                        peer_status: "尚未连接对端".into(),
                        network_epoch: 0,
                        peer_generations: HashMap::new(),
                        peer_states: HashMap::new(),
                        tunnel_states: HashMap::new(),
                        tunnel_last_errors: HashMap::new(),
                        task_rows: Vec::new(),
                        task_snapshot: Vec::new(),
                        task_search,
                        task_filter: Default::default(),
                        clearing_history: false,
                        outcome_alerts: Default::default(),
                        native_alerts: notifications::NativeAlerts::new(initial_notifications),
                        notification_note: if initial_notifications {
                            "正在检查系统通知权限…"
                        } else {
                            "系统通知已关闭"
                        }
                        .into(),
                        expanded_groups: HashSet::new(),
                        selected_task: None,
                        detail_selection: None,
                        task_details: None,
                        detail_page: 0,
                        revealing_task: false,
                        queue_status: "正在载入任务…".into(),
                        receive_space_status: "接收预算尚未预约".into(),
                        speed_views: Default::default(),
                        speedtest_upload_result: None,
                        speed_peer: None,
                        speed_request_until: None,
                        show_speed_test_panel: false,
                        show_speed_duration_menu: false,
                        show_settings: !has_saved_network_config,
                        show_settings_home: show_initial_password,
                        pending_resumes: HashMap::new(),
                        applied_receive_root: initial_receive_root,
                        task_scroll: Default::default(),
                        status: initial_status.into(),
                        focus_handle: cx.focus_handle(),
                    }
                })
            },
        );

        match window {
            Ok(window) => {
                window
                    .update(cx, move |shell, window, cx| {
                        let field = if shell.show_settings {
                            &shell.signal_host
                        } else {
                            &shell.peer_id
                        };
                        window.focus(&field.focus_handle(cx));
                        if !start_hidden {
                            cx.activate(true);
                        }
                        shell.observe_tasks(cx);
                        if let Some(config) = startup_session_config {
                            shell.start_network_session(config, cx);
                        }
                    })
                    .expect("新建 GPUI 窗口后初始化焦点失败");
                background::install(window, cx, start_hidden);
                cx.on_action(|_: &Quit, cx| background::request_quit(cx));
            }
            Err(error) => {
                eprintln!("打开 GPUI 窗口失败：{error}");
                cx.quit();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{
        concurrency_value_replacement, marked_selection_to_utf8, mouse_index_for_layout,
        password_display, utf8_offset_from_utf16, utf16_offset_from_utf8,
    };

    #[test]
    fn password_display_masks_ascii_without_changing_cursor_offsets() {
        let value = "A9b8C7";
        assert_eq!(password_display(value, false), "******");
        assert_eq!(password_display(value, true), value);
        assert_eq!(password_display(value, false).len(), value.len());
        assert_eq!(password_display("", false), "");
        let hidden = password_display(value, false);
        assert_eq!(mouse_index_for_layout(&hidden, &hidden, 3), Some(3));
        assert_eq!(
            mouse_index_for_layout(&hidden, &hidden, 99),
            Some(value.len())
        );
        assert_eq!(
            mouse_index_for_layout(&password_display("A9", false), &hidden, 3),
            None
        );
    }
    #[test]
    fn concurrency_input_only_accepts_single_values_from_one_to_three() {
        assert_eq!(
            concurrency_value_replacement("1", 1..1, "3"),
            Some((0..1, "3".to_owned()))
        );
        assert_eq!(concurrency_value_replacement("1", 1..1, "4"), None);
        assert_eq!(
            concurrency_value_replacement("2", 0..1, ""),
            Some((0..1, "2".to_owned()))
        );
        assert_eq!(
            concurrency_value_replacement("1", 1..1, "invalid3"),
            Some((0..1, "3".to_owned()))
        );
    }

    #[test]
    fn utf16_offsets_preserve_cjk_and_surrogate_pairs() {
        let content = "甲🙂乙";
        assert_eq!(utf16_offset_from_utf8(content, "甲".len()), 1);
        assert_eq!(utf16_offset_from_utf8(content, "甲🙂".len()), 3);
        assert_eq!(utf8_offset_from_utf16(content, 1), "甲".len());
        assert_eq!(utf8_offset_from_utf16(content, 3), "甲🙂".len());
    }

    #[test]
    fn ime_selection_is_relative_to_new_text_after_multibyte_prefix() {
        let content = "前🙂";
        let new_text = "中🙂文";
        let insertion_offset = content.len();
        let selected = marked_selection_to_utf8(insertion_offset, new_text, &(1..3));
        let combined = format!("{content}{new_text}");

        assert_eq!(&combined[selected], "🙂");
    }

    #[test]
    fn stale_ascii_layout_is_rejected_after_content_becomes_short_emoji() {
        assert_eq!(mouse_index_for_layout("🙂", "old ASCII content", 3), None);
    }

    #[test]
    fn stale_long_layout_is_rejected_after_content_becomes_short_text() {
        assert_eq!(
            mouse_index_for_layout("短", "a much longer old value", 3),
            None
        );
    }

    #[test]
    fn placeholder_layout_is_rejected_when_content_is_empty() {
        assert_eq!(
            mouse_index_for_layout("", "输入或粘贴对端 ID（仅壳层输入）", 3),
            None
        );
    }

    #[test]
    fn current_layout_maps_internal_utf8_offset_to_a_boundary() {
        assert_eq!(mouse_index_for_layout("🙂", "🙂", 3), Some(0));
    }
}
