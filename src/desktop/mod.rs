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
pub(in crate::desktop) mod config;
#[cfg(test)]
mod e2e;
mod files;
mod frame_budget;
pub(in crate::desktop) mod instance_lock;
mod network_state;
#[allow(dead_code)] // T005 wire guards are consumed by transfer/speed business in T006-T009.
mod protocol;
mod publish;
mod queue;
pub(crate) mod secure_fs;
mod session;
mod speed;
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
mod tunnel;
mod ui;
mod ui_model;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use std::{net::SocketAddr, ops::Range, path::PathBuf};

use crate::identity::{Identity, NodeId};
use config::{
    AllowedForwardTarget, AppPaths, ConfigError, DesktopConfig, SettingsDraft, SpeedtestDirection,
    TunnelRule,
};
use instance_lock::InstanceLock;
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
        let (settings, config_note, can_save_settings, has_saved_network_config) =
            match DesktopConfig::load(&config_file) {
                Ok(Some(config)) => {
                    let (settings, note, can_save) = config::restore_saved_settings(config);
                    (settings, note, can_save, true)
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

struct TextField {
    focus_handle: FocusHandle,
    content: SharedString,
    placeholder: SharedString,
    concurrency_value_input: bool,
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
            selected_range: 0..0,
            selection_reversed: false,
            marked_range: None,
            last_layout: None,
            last_bounds: None,
            is_selecting: false,
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
        if line.text != self.content {
            return None;
        };
        if position.y < bounds.top() {
            return Some(0);
        }
        if position.y > bounds.bottom() {
            return Some(self.content.len());
        }
        mouse_index_for_layout(
            &self.content,
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
        Some(self.content[range].to_string())
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
        let content = input.content.clone();
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
    concurrency_input: Entity<TextField>,
    signal_host: Entity<TextField>,
    signal_port: Entity<TextField>,
    allowed_name: Entity<TextField>,
    allowed_target: Entity<TextField>,
    tunnel_name: Entity<TextField>,
    tunnel_peer: Entity<TextField>,
    tunnel_listen: Entity<TextField>,
    tunnel_target: Entity<TextField>,
    editing_allowed_id: Option<String>,
    editing_tunnel_id: Option<String>,
    selected_files: Vec<PathBuf>,
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
    peer_status: SharedString,
    network_epoch: u64,
    peer_generations: HashMap<NodeId, u64>,
    peer_states: HashMap<NodeId, network_state::PeerLifecycle>,
    tunnel_states: HashMap<String, session::TunnelRuntimeState>,
    tunnel_last_errors: HashMap<String, String>,
    task_rows: Vec<ui_model::ListRow>,
    expanded_groups: HashSet<task_model::TaskId>,
    selected_task: Option<task_model::TaskId>,
    queue_status: SharedString,
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
                self.allowed_name.clone(),
                self.allowed_target.clone(),
                self.tunnel_name.clone(),
                self.tunnel_peer.clone(),
                self.tunnel_listen.clone(),
                self.tunnel_target.clone(),
                self.peer_id.clone(),
            ]
        } else {
            vec![self.peer_id.clone()]
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
        cx.notify();
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
                                shell.task_rows = snapshot.list(&shell.expanded_groups);
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
    fn authenticated_peer(&mut self, cx: &mut Context<Self>) -> Option<NodeId> {
        let result = NodeId::from_hex(self.peer_id.read(cx).content.trim());
        let Ok(peer) = result else {
            self.set_status("请先输入有效的完整对端 ID 并连接", cx);
            return None;
        };
        if !matches!(
            self.peer_states.get(&peer),
            Some(network_state::PeerLifecycle::Connected)
        ) {
            self.set_status("请先连接并等待对端身份认证完成", cx);
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
                    if !matches!(
                        self.peer_states.get(&row.peer),
                        Some(network_state::PeerLifecycle::Connected)
                    ) {
                        s.connect_peer(row.peer)?;
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
    fn confirm_delete_received_file(
        &mut self,
        id: task_model::TaskId,
        name: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
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
                return;
            }
            let delete_id = id.clone();
            let result = background
                .spawn(async move { service.delete_completed_receive_file(&delete_id) })
                .await;
            let _ = shell.update(cx, move |shell, cx| match result {
                Ok(()) => {
                    if shell.selected_task.as_ref() == Some(&id) {
                        shell.selected_task = None;
                    }
                    shell.set_status("已删除接收文件，并移除完成记录", cx);
                }
                Err(error) => shell.set_status(format!("删除接收文件失败：{error}"), cx),
            });
        })
        .detach();
    }
    fn task_row(&mut self, index: usize, cx: &mut Context<Self>) -> gpui::Div {
        let row = self.task_rows[index].clone();
        match row {
            ui_model::ListRow::Group(group) => {
                let expanded = self.expanded_groups.contains(&group.id);
                let id = group.id.clone();
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
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                            if !shell.expanded_groups.remove(&id) {
                                shell.expanded_groups.insert(id.clone());
                            }
                            cx.notify();
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
                let mut actions = div().w(px(64.)).flex().items_center().justify_end().gap_1();
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
        self.config_note = "端口转发列表有未保存改动，请点击“保存并应用”".into();
        self.set_status("端口转发配置尚未保存", cx);
    }

    fn cancel_allowed_edit(&mut self, cx: &mut Context<Self>) {
        self.editing_allowed_id = None;
        Self::set_text_field(&self.allowed_name, "", cx);
        Self::set_text_field(&self.allowed_target, "", cx);
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
        self.editing_allowed_id = Some(id);
        Self::set_text_field(&self.allowed_name, name, cx);
        Self::set_text_field(&self.allowed_target, target, cx);
        cx.notify();
    }

    fn save_allowed_target(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
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
            }
        } else {
            self.settings
                .allowed_forward_targets
                .push(AllowedForwardTarget::new(name, target));
        }
        self.cancel_allowed_edit(cx);
        self.note_forward_settings_changed(cx);
    }

    fn toggle_allowed_target(&mut self, id: String, cx: &mut Context<Self>) {
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

    fn toggle_tunnel_enabled(&mut self, id: String, cx: &mut Context<Self>) {
        if let Some(rule) = self
            .settings
            .tunnel_rules
            .iter_mut()
            .find(|rule| rule.id == id)
        {
            rule.enabled = !rule.enabled;
            self.note_forward_settings_changed(cx);
        }
    }

    fn toggle_tunnel_auto_start(&mut self, id: String, cx: &mut Context<Self>) {
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
        self.settings.tunnel_rules.retain(|rule| rule.id != id);
        if self.editing_tunnel_id.as_deref() == Some(id.as_str()) {
            self.cancel_tunnel_edit(cx);
        }
        self.tunnel_states
            .insert(id, session::TunnelRuntimeState::Stopped);
        self.note_forward_settings_changed(cx);
    }

    fn toggle_tunnel_runtime(&mut self, id: String, cx: &mut Context<Self>) {
        let running = matches!(
            self.tunnel_states.get(&id),
            Some(session::TunnelRuntimeState::Starting | session::TunnelRuntimeState::Running)
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
        config.transfer = self.transfer_service.clone();
        config.allowed_forward_targets = self.settings.enabled_forward_targets();
        config.tunnel_rules = self.settings.tunnel_rules.clone();
        match session::spawn(identity, config) {
            Ok((handle, mut session_events)) => {
                self.network_epoch = self.network_epoch.wrapping_add(1);
                let network_epoch = self.network_epoch;
                self.peer_generations.clear();
                self.peer_states.clear();
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
                                    session::SessionEvent::Lifecycle(lifecycle) => {
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
                                        shell.peer_generations.insert(peer, generation);
                                        shell.peer_states.insert(peer, state.clone());
                                        if matches!(state,network_state::PeerLifecycle::Connected) {
                                            if let Some(ids)=shell.pending_resumes.remove(&peer) {
                                                for id in ids {if let Some(session)=&shell.network_session && let Err(e)=session.resume_task(peer,id){shell.set_status(e,cx);}}
                                            }
                                        }else if matches!(state,network_state::PeerLifecycle::Disconnected|network_state::PeerLifecycle::Failed(_)){shell.pending_resumes.remove(&peer);}
                                        let label = match state {
                                            network_state::PeerLifecycle::PeerPending => {
                                                "等待对端候选地址".to_owned()
                                            }
                                            network_state::PeerLifecycle::Punching => {
                                                "正在验证 UDP 打洞来源".to_owned()
                                            }
                                            network_state::PeerLifecycle::Authenticating => {
                                                "正在执行 QUIC 与身份认证".to_owned()
                                            }
                                            network_state::PeerLifecycle::Negotiating => {
                                                "正在协商桌面版本与能力".to_owned()
                                            }
                                            network_state::PeerLifecycle::Connected => {
                                                "已认证直连".to_owned()
                                            }
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
        let peer_text = self.peer_id.read(cx).content.to_string();
        let peer = match NodeId::from_hex(peer_text.trim()) {
            Ok(peer) => peer,
            Err(error) => {
                self.set_status(format!("对端 Node ID 无效：{error}"), cx);
                return;
            }
        };
        if self
            .identity
            .as_ref()
            .is_some_and(|identity| identity.node_id() == peer)
        {
            self.set_status("不能连接本机 Node ID", cx);
            return;
        }
        let Some(session) = self.network_session.as_ref() else {
            self.set_status("请先保存有效的信令配置；网络会话尚未启动", cx);
            return;
        };
        match session.connect_peer(peer) {
            Ok(()) => self.set_status(format!("已提交对端 {} 的连接请求", peer.short()), cx),
            Err(error) => self.set_status(error, cx),
        }
    }

    fn copy_node_id(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(identity_id) = self.identity_id.as_ref() {
            cx.write_to_clipboard(ClipboardItem::new_string(identity_id.clone()));
            self.set_status("已复制完整本机 Node ID", cx);
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
        if !self.can_save_settings || self.is_saving_settings {
            self.set_status("当前配置不可保存；请检查配置诊断信息", cx);
            return;
        }

        let mut draft = self.settings.clone();
        draft.signal_host = self.signal_host.read(cx).content.to_string();
        draft.signal_port = self.signal_port.read(cx).content.to_string();
        let config_file = self.config_file.clone();
        let signal_server = signal_server_spec(&draft.signal_host, &draft.signal_port);
        let saved_receive_root = draft.receive_directory.clone();
        let saved_send_limit = draft.send_concurrency;
        let signal_changed = draft.signal_host != self.settings.signal_host
            || draft.signal_port != self.settings.signal_port;
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
                                match session.reconfigure_signal(signal_server.clone()) {
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
                                config.allowed_forward_targets =
                                    shell.settings.enabled_forward_targets();
                                config.tunnel_rules = shell.settings.tunnel_rules.clone();
                                shell.start_network_session(config, cx);
                            }
                        }
                        Err(error) => {
                            shell.set_status(format!("设置未保存：{error}"), cx);
                        }
                    }
                })
                .ok();
        })
        .detach();
    }

    fn choose_files(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.pick_files(cx);
    }
    fn pick_files(&mut self, cx: &mut Context<Self>) {
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
        let task = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: Some("选择要发送的文件".into()),
        });
        cx.spawn(async move |shell, cx| {
            let result = task.await;
            shell
                .update(cx, |shell, cx| match result {
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
                })
                .ok();
        })
        .detach();
    }

    fn choose_folder(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.pick_folder(cx);
    }
    fn pick_folder(&mut self, cx: &mut Context<Self>) {
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
        let task = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("选择要发送的目录".into()),
        });
        cx.spawn(async move |shell, cx| {
            let result = task.await;
            shell
                .update(cx, |shell, cx| match result {
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
                                    .and_then(|session| session.send_directory(peer, path.clone()));
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
                                shell
                                    .set_status("所选目录路径编码不受支持；未保存或转换该路径", cx);
                            }
                        } else {
                            shell.set_status("未选择目录", cx);
                        }
                    }
                    Ok(Ok(None)) => shell.set_status("已取消目录选择", cx),
                    Ok(Err(error)) => shell.set_status(format!("目录选择失败：{error:?}"), cx),
                    Err(_) => shell.set_status("目录选择任务已取消", cx),
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
        let task = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("选择接收目录".into()),
        });
        cx.spawn(async move |shell, cx| {
            let result = task.await;
            shell
                .update(cx, |shell, cx| match result {
                    Ok(Ok(Some(mut paths))) => {
                        if let Some(path) = paths.pop() {
                            if let Some(path_text) = path.to_str() {
                                shell.settings.receive_directory = Some(path.to_path_buf());
                                shell.config_note =
                                    "已选择新接收目录；保存时重新验证写能力，仅影响新任务".into();
                                shell.set_status(
                                    format!("接收目录已选择 {path_text}；保存后用于新任务"),
                                    cx,
                                );
                            } else {
                                shell
                                    .set_status("所选接收目录路径编码不受支持；请改选其它目录", cx);
                            }
                        } else {
                            shell.set_status("未选择接收目录", cx);
                        }
                    }
                    Ok(Ok(None)) => shell.set_status("已取消接收目录选择", cx),
                    Ok(Err(error)) => shell.set_status(format!("接收目录选择失败：{error:?}"), cx),
                    Err(_) => shell.set_status("接收目录选择任务已取消", cx),
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
        let peer_is_valid = NodeId::from_hex(self.peer_id.read(cx).content.trim())
            .ok()
            .is_some_and(|peer| {
                self.identity
                    .as_ref()
                    .is_none_or(|identity| identity.node_id() != peer)
            });
        let peer_is_active = NodeId::from_hex(self.peer_id.read(cx).content.trim())
            .ok()
            .and_then(|peer| self.peer_states.get(&peer))
            .is_some_and(network_state::PeerLifecycle::is_active);
        let enabled = self.identity.is_some()
            && self.network_session.is_some()
            && peer_is_valid
            && !peer_is_active;
        ui_components::primary_button("连接", enabled)
            .on_mouse_up(MouseButton::Left, cx.listener(Self::connect_peer))
    }

    fn header_status(&self, cx: &Context<Self>) -> (String, ui_components::StatusTone) {
        if let Ok(peer) = NodeId::from_hex(self.peer_id.read(cx).content.trim()) {
            match self.peer_states.get(&peer) {
                Some(network_state::PeerLifecycle::Connected) => {
                    return ("已连接".into(), ui_components::StatusTone::Success);
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

        if self
            .peer_states
            .values()
            .any(|state| matches!(state, network_state::PeerLifecycle::Connected))
        {
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
                    .child(ui_components::secondary_button("设置", true).on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|shell, _: &MouseUpEvent, _, cx| shell.open_settings_home(cx)),
                    )),
            )
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
            .child(self.advanced_network_card(window, cx))
    }

    fn connection_card(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let identity = self
            .identity_id
            .clone()
            .unwrap_or_else(|| "身份不可用".to_owned());
        let connected = NodeId::from_hex(self.peer_id.read(cx).content.trim())
            .ok()
            .is_some_and(|peer| {
                matches!(
                    self.peer_states.get(&peer),
                    Some(network_state::PeerLifecycle::Connected)
                )
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
                    .on_mouse_up(MouseButton::Left, cx.listener(Self::copy_node_id)),
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
                    .on_mouse_up(MouseButton::Left, cx.listener(Self::copy_node_id)),
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

        let fields = div().flex().flex_col().gap_2().child(local).child(peer);

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
            .h(px(184.))
            .p(px(12.))
            .gap_2()
            .child(ui_components::section_header(
                "↔",
                "连接设备",
                "输入完整设备 ID，等待身份认证后开始传输",
            ))
            .child(fields)
            .child(
                div()
                    .w_full()
                    .flex()
                    .justify_start()
                    .child(speed_test_action),
            )
    }

    fn transfer_card(&mut self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let connected = NodeId::from_hex(self.peer_id.read(cx).content.trim())
            .ok()
            .is_some_and(|peer| {
                matches!(
                    self.peer_states.get(&peer),
                    Some(network_state::PeerLifecycle::Connected)
                )
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
        let transfer_toolbar = div()
            .flex()
            .items_center()
            .justify_between()
            .gap_3()
            .child(file_actions)
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
                            .child(format!("传输列表（{} 个任务）", self.task_rows.len())),
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
                        .child("暂无传输任务"),
                )
                .child(div().text_xs().child("连接设备后选择文件或文件夹开始传输"))
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
        let can_start = NodeId::from_hex(self.peer_id.read(cx).content.trim())
            .ok()
            .is_some_and(|peer| {
                matches!(
                    self.peer_states.get(&peer),
                    Some(network_state::PeerLifecycle::Connected)
                )
            })
            && self.transfer_service.is_some()
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
                                .child(entry.target.to_string()),
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
                session::TunnelRuntimeState::Starting | session::TunnelRuntimeState::Running
            );
            let (runtime_label, runtime_color) = match &runtime {
                session::TunnelRuntimeState::Starting => ("正在启动", ui_theme::WARNING),
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
                    .child("该规则允许已认证对端通过本机访问此目标，请仅添加你信任的服务。"),
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
            format!("{}:{}", host.trim(), port.trim())
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

        div()
            .size_full()
            .id("desktop-shell")
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
            .child(self.connection_receive_row(window, cx))
            .when_some(speed_card, |page, speed_card| page.child(speed_card))
            .child(self.transfer_card(window, cx))
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
pub fn run() {
    let startup = match DesktopStartup::load() {
        Ok(startup) => startup,
        Err(error) => {
            eprintln!("桌面启动失败：{error}");
            return;
        }
    };

    Application::new().run(move |cx: &mut App| {
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
        let initial_receive_root = settings.receive_directory.clone();
        let initial_concurrency = settings.send_concurrency;
        let initial_host = settings.signal_host.clone();
        let initial_port = settings.signal_port.clone();
        let startup_session_config = if has_saved_network_config && identity.is_some() {
            Some(session::DesktopSessionConfig::new(signal_server_spec(
                &settings.signal_host,
                &settings.signal_port,
            )))
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
        let window = cx.open_window(
            WindowOptions {
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
                let peer_id = cx.new(|cx| TextField::new(cx, "输入对方 ID"));
                let concurrency_input =
                    cx.new(|cx| TextField::new_concurrency_value(cx, initial_concurrency));
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
                let allowed_name = cx.new(|cx| TextField::new(cx, "例如：SSH"));
                let allowed_target = cx.new(|cx| TextField::new(cx, "127.0.0.1:22"));
                let tunnel_name = cx.new(|cx| TextField::new(cx, "例如：家里 SSH"));
                let tunnel_peer = cx.new(|cx| TextField::new(cx, "完整的对端 Node ID"));
                let tunnel_listen = cx.new(|cx| {
                    let mut field = TextField::new(cx, "127.0.0.1:2222");
                    field.content = "127.0.0.1:2222".into();
                    field
                });
                let tunnel_target = cx.new(|cx| TextField::new(cx, "127.0.0.1:22"));
                cx.new(|cx| {
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
                        concurrency_input,
                        signal_host,
                        signal_port,
                        allowed_name,
                        allowed_target,
                        tunnel_name,
                        tunnel_peer,
                        tunnel_listen,
                        tunnel_target,
                        editing_allowed_id: None,
                        editing_tunnel_id: None,
                        selected_files: Vec::new(),
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
                        peer_status: "尚未连接对端".into(),
                        network_epoch: 0,
                        peer_generations: HashMap::new(),
                        peer_states: HashMap::new(),
                        tunnel_states: HashMap::new(),
                        tunnel_last_errors: HashMap::new(),
                        task_rows: Vec::new(),
                        expanded_groups: HashSet::new(),
                        selected_task: None,
                        queue_status: "正在载入任务…".into(),
                        speed_views: Default::default(),
                        speedtest_upload_result: None,
                        speed_peer: None,
                        speed_request_until: None,
                        show_speed_test_panel: false,
                        show_speed_duration_menu: false,
                        show_settings: !has_saved_network_config,
                        show_settings_home: false,
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
                        cx.activate(true);
                        shell.observe_tasks(cx);
                        if let Some(config) = startup_session_config {
                            shell.start_network_session(config, cx);
                        }
                    })
                    .expect("新建 GPUI 窗口后初始化焦点失败");
                cx.on_action(|_: &Quit, cx| cx.quit());
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
        utf8_offset_from_utf16, utf16_offset_from_utf8,
    };

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
