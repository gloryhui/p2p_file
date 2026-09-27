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
mod ui;
mod ui_model;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use std::{ops::Range, path::PathBuf};

use crate::identity::{Identity, NodeId};
use config::{AppPaths, ConfigError, DesktopConfig, SettingsDraft, SpeedtestDirection};
use instance_lock::InstanceLock;
use task_store::TaskStore;
use ui::{components as ui_components, theme as ui_theme};

use gpui::{
    App, Application, Bounds, ClipboardItem, Context, CursorStyle, ElementId, ElementInputHandler,
    Entity, EntityInputHandler, FocusHandle, Focusable, GlobalElementId, KeyBinding, LayoutId,
    MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent, PaintQuad, PathPromptOptions,
    Pixels, Point, ShapedLine, SharedString, Style, TextRun, UTF16Selection, UnderlineStyle,
    Window, WindowBounds, WindowOptions, actions, div, fill, hsla, point, prelude::*, px, relative,
    rgb, rgba, size, white,
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
            selected_range: 0..0,
            selection_reversed: false,
            marked_range: None,
            last_layout: None,
            last_bounds: None,
            is_selecting: false,
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

        self.content =
            (self.content[0..range.start].to_owned() + new_text + &self.content[range.end..])
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

        self.content =
            (self.content[0..range.start].to_owned() + new_text + &self.content[range.end..])
                .into();
        if !new_text.is_empty() {
            self.marked_range = Some(range.start..range.start + new_text.len());
        } else {
            self.marked_range = None;
        }
        self.selected_range = new_selected_range_utf16
            .as_ref()
            .map(|range_utf16| marked_selection_to_utf8(range.start, new_text, range_utf16))
            .unwrap_or_else(|| range.start + new_text.len()..range.start + new_text.len());
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
        div()
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
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .line_height(px(26.))
            .text_size(px(16.))
            .child(
                div()
                    .h(px(40.))
                    .w_full()
                    .p(px(7.))
                    .bg(white())
                    .child(TextFieldElement { input: cx.entity() }),
            )
    }
}

impl Focusable for TextField {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

struct DesktopShell {
    peer_id: Entity<TextField>,
    signal_host: Entity<TextField>,
    signal_port: Entity<TextField>,
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
    task_rows: Vec<ui_model::ListRow>,
    expanded_groups: HashSet<task_model::TaskId>,
    selected_task: Option<task_model::TaskId>,
    queue_status: SharedString,
    speed_views: ui_model::SpeedViews,
    speed_peer: Option<NodeId>,
    speed_request_until: Option<Instant>,
    show_settings: bool,
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
    fn current_peer_label(&self, cx: &Context<Self>) -> String {
        let Ok(peer) = NodeId::from_hex(self.peer_id.read(cx).content.trim()) else {
            let connected = self
                .peer_states
                .values()
                .filter(|state| matches!(state, network_state::PeerLifecycle::Connected))
                .count();
            return if connected == 0 {
                "输入对端 ID 后连接；也可以被动接收对端文件".into()
            } else {
                format!("已有 {connected} 个对端完成身份认证；本机可被动接收")
            };
        };
        let state = match self.peer_states.get(&peer) {
            Some(network_state::PeerLifecycle::Connected) => "已认证直连".to_owned(),
            Some(network_state::PeerLifecycle::PeerPending) => "等待对端上线".into(),
            Some(network_state::PeerLifecycle::Punching) => "正在建立直连".into(),
            Some(network_state::PeerLifecycle::Authenticating) => "正在核对身份".into(),
            Some(network_state::PeerLifecycle::Negotiating) => "正在核对版本".into(),
            Some(network_state::PeerLifecycle::Disconnected) => "连接已断开".into(),
            Some(network_state::PeerLifecycle::Failed(error)) => format!("连接失败：{error}"),
            None => "尚未连接".into(),
        };
        format!("对端 {}：{state}", peer.short())
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
        let direction = match self.settings.speedtest_direction {
            SpeedtestDirection::Upload => protocol::SpeedDirection::Upload,
            SpeedtestDirection::Download => protocol::SpeedDirection::Download,
        };
        let result = self
            .network_session
            .as_ref()
            .ok_or("网络会话已关闭".to_owned())
            .and_then(|s| s.start_speed(peer, direction, self.settings.speedtest_seconds));
        match result {
            Ok(()) => {
                self.speed_peer = Some(peer);
                self.speed_request_until = Some(Instant::now() + Duration::from_secs(6));
                self.set_status("正在请求测速；有文件活动时需先暂停，不会自动暂停任务", cx);
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
    fn task_row(&mut self, index: usize, cx: &mut Context<Self>) -> gpui::Div {
        let row = self.task_rows[index].clone();
        match row {
            ui_model::ListRow::Group(group) => {
                let expanded = self.expanded_groups.contains(&group.id);
                let id = group.id.clone();
                div()
                    .h(px(72.))
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
                let can_pause = task.can_pause();
                let can_continue = task.can_continue();
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
                let action = if can_pause {
                    ui_components::secondary_button("暂停", true).on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                            shell.task_action(pause.clone(), false, cx);
                        }),
                    )
                } else if can_continue {
                    ui_components::secondary_button("继续", true).on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                            shell.task_action(resume.clone(), true, cx);
                        }),
                    )
                } else {
                    div().w(px(64.))
                };

                div()
                    .h(px(72.))
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
                            .gap_1()
                            .child(
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
                                            .py(px(2.))
                                            .rounded_md()
                                            .bg(rgb(status_background))
                                            .text_xs()
                                            .text_color(rgb(status_color))
                                            .child(task.state_label()),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(ui_components::progress_bar(progress))
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
                                    .text_xs()
                                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                    .truncate()
                                    .child(metadata),
                            ),
                    )
                    .child(action)
            }
        }
    }
    fn set_status(&mut self, status: impl Into<SharedString>, cx: &mut Context<Self>) {
        self.status = status.into();
        cx.notify();
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
        match session::spawn(identity, config) {
            Ok((handle, mut session_events)) => {
                self.network_epoch = self.network_epoch.wrapping_add(1);
                let network_epoch = self.network_epoch;
                self.peer_generations.clear();
                self.peer_states.clear();
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
                                    session::SessionEvent::Diagnostic(detail) => {
                                        if detail != "信令心跳已确认" {shell.set_status(detail, cx);}
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

    fn cycle_concurrency(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.change_concurrency(cx);
    }
    fn change_concurrency(&mut self, cx: &mut Context<Self>) {
        if self.is_saving_settings {
            return;
        }
        self.settings.send_concurrency = self.settings.send_concurrency % 3 + 1;
        cx.notify();
    }

    fn cycle_speedtest_duration(
        &mut self,
        _: &MouseUpEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.change_duration(cx);
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
            SpeedtestDirection::Upload => SpeedtestDirection::Download,
            SpeedtestDirection::Download => SpeedtestDirection::Upload,
        };
        cx.notify();
    }

    fn set_speed_direction(&mut self, direction: SpeedtestDirection, cx: &mut Context<Self>) {
        if self.is_saving_settings {
            return;
        }
        self.settings.speedtest_direction = direction;
        cx.notify();
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
                            shell.config_note = "设置已保存；接收目录写能力检查通过。".into();
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
                                let config = session::DesktopSessionConfig::new(signal_server);
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

    fn enqueue_dropped_paths(&mut self, paths: &[PathBuf], cx: &mut Context<Self>) {
        if paths.is_empty() {
            self.set_status("没有可传输的拖入路径", cx);
            return;
        }
        if self
            .speed_views
            .0
            .values()
            .any(|view| view.snapshot.status == speed::SpeedStatus::Running)
        {
            self.set_status("测速正在进行；请先取消或等待测速结束后再添加文件", cx);
            return;
        }
        if paths.iter().any(|path| path.to_str().is_none()) {
            self.set_status("拖入路径编码不受支持；没有提交任何路径", cx);
            return;
        }
        let Some(peer) = self.authenticated_peer(cx) else {
            return;
        };
        let Some(session) = self.network_session.clone() else {
            self.set_status("网络会话已关闭；没有提交拖入路径", cx);
            return;
        };

        let mut submitted = 0usize;
        for path in paths {
            let result = if path.is_dir() {
                session.send_directory(peer, path.clone())
            } else if path.is_file() {
                session.send_file(peer, path.clone())
            } else {
                Err(format!("路径不是可读取的文件或目录：{}", path.display()))
            };
            match result {
                Ok(()) => submitted += 1,
                Err(error) => {
                    self.set_status(
                        if submitted == 0 {
                            format!("拖入路径未能提交：{error}")
                        } else {
                            format!("已提交 {submitted} 个路径，后续提交失败：{error}")
                        },
                        cx,
                    );
                    return;
                }
            }
        }
        self.selected_files = paths
            .iter()
            .filter(|path| path.is_file())
            .cloned()
            .collect();
        self.selected_folder = paths.iter().find(|path| path.is_dir()).cloned();
        self.set_status(
            format!(
                "已提交 {submitted} 个拖入路径；传输对象绑定到已认证对端 {}",
                peer.short()
            ),
            cx,
        );
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

    fn path_line(label: &str, path: Option<&PathBuf>) -> gpui::Div {
        let value = path
            .and_then(|path| path.to_str())
            .unwrap_or("尚未选择")
            .to_owned();
        div()
            .flex()
            .gap_2()
            .text_xs()
            .text_color(rgb(ui_theme::TEXT_SECONDARY))
            .child(format!("{label}："))
            .child(div().flex_1().min_w_0().truncate().child(value))
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

    fn copy_identity_button(&self, cx: &mut Context<Self>) -> impl IntoElement {
        ui_components::icon_button("复制", self.identity_id.is_some())
            .on_mouse_up(MouseButton::Left, cx.listener(Self::copy_node_id))
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
        ui_components::primary_button("连接设备", enabled)
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
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .w(px(40.))
                            .h(px(40.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded_lg()
                            .bg(rgb(ui_theme::PRIMARY))
                            .text_size(px(23.))
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_color(white())
                            .child("↔"),
                    )
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
                                    .child("P2P File"),
                            )
                            .child(
                                div()
                                    .text_size(px(13.))
                                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                    .child("设备之间，直接传文件"),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(ui_components::status_badge(status, tone))
                    .child(ui_components::secondary_button("设置", true).on_mouse_up(
                        MouseButton::Left,
                        cx.listener(|shell, _: &MouseUpEvent, window, cx| {
                            shell.toggle_settings(window, cx)
                        }),
                    )),
            )
    }

    fn connection_card(&self, window: &Window, cx: &mut Context<Self>) -> gpui::Div {
        let identity = self
            .identity_id
            .clone()
            .unwrap_or_else(|| "身份不可用".to_owned());
        let (peer_label, peer_tone) = self.header_status(cx);
        let width = window.viewport_size().width / px(window.scale_factor());
        let horizontal = width >= 900.;

        let local = div()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_2()
            .child(ui_components::field_label("本机 ID"))
            .child(
                div()
                    .w_full()
                    .h(px(44.))
                    .flex()
                    .items_center()
                    .gap_2()
                    .px(px(8.))
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(ui_theme::BORDER))
                    .bg(rgb(ui_theme::SURFACE_SUBTLE))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_sm()
                            .text_color(rgb(ui_theme::TEXT))
                            .child(identity),
                    )
                    .child(self.copy_identity_button(cx)),
            );

        let peer = div()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_2()
            .child(ui_components::field_label("对端设备 ID"))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(Self::text_field_frame(&self.peer_id, window, cx))
                    .child(self.connect_peer_button(cx)),
            );

        let fields = if horizontal {
            div()
                .flex()
                .items_start()
                .gap_4()
                .child(local)
                .child(div().w(px(1.)).h(px(64.)).bg(rgb(ui_theme::BORDER)))
                .child(peer)
        } else {
            div().flex().flex_col().gap_3().child(local).child(peer)
        };

        ui_components::card()
            .child(ui_components::section_header(
                "↔",
                "连接设备",
                "输入完整设备 ID，等待身份认证后开始传输",
            ))
            .child(fields)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(ui_components::status_badge(peer_label, peer_tone))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_xs()
                            .text_color(rgb(ui_theme::TEXT_SECONDARY))
                            .truncate()
                            .child(self.current_peer_label(cx)),
                    ),
            )
    }

    fn transfer_card(&mut self, cx: &mut Context<Self>) -> gpui::Div {
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
        let task_count = self.task_rows.len();
        let list_height = task_count.clamp(1, 4) as f32 * 72.;

        let actions = div()
            .flex()
            .items_center()
            .gap_2()
            .child(
                ui_components::secondary_button("选择文件", enabled)
                    .on_mouse_up(MouseButton::Left, cx.listener(Self::choose_files)),
            )
            .child(
                ui_components::secondary_button("选择文件夹", enabled)
                    .on_mouse_up(MouseButton::Left, cx.listener(Self::choose_folder)),
            )
            .child(
                ui_components::secondary_button(
                    format!("并发 {}", self.settings.send_concurrency),
                    !self.is_saving_settings,
                )
                .on_mouse_up(MouseButton::Left, cx.listener(Self::cycle_concurrency)),
            );

        let drop_zone = div()
            .w_full()
            .h(px(104.))
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap_2()
            .rounded_lg()
            .border_1()
            .border_dashed()
            .border_color(rgb(if enabled {
                ui_theme::DROP_BORDER
            } else {
                ui_theme::BORDER
            }))
            .bg(rgb(if enabled {
                ui_theme::SURFACE_SUBTLE
            } else {
                ui_theme::DISABLED_BG
            }))
            .child(
                div()
                    .w(px(34.))
                    .h(px(34.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .rounded_full()
                    .bg(rgb(ui_theme::PRIMARY_SOFT))
                    .text_size(px(22.))
                    .font_weight(gpui::FontWeight::BOLD)
                    .text_color(rgb(ui_theme::PRIMARY))
                    .child("↑"),
            )
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::MEDIUM)
                    .text_color(rgb(ui_theme::TEXT))
                    .child(if enabled {
                        "将文件或文件夹拖到此处"
                    } else if connected {
                        "测速完成或取消后再添加待发送文件"
                    } else {
                        "连接设备后可添加待发送文件"
                    }),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child(if enabled {
                        "也可以使用右上角按钮打开系统选择器"
                    } else {
                        "本机仍可被动接收对端发送的文件"
                    }),
            )
            .drag_over::<gpui::ExternalPaths>(move |style, _, _, _| {
                if enabled {
                    style
                        .bg(rgb(ui_theme::PRIMARY_SOFT))
                        .border_color(rgb(ui_theme::PRIMARY))
                } else {
                    style
                }
            })
            .can_drop(move |_, _, _| enabled)
            .on_drop(cx.listener(|shell, paths: &gpui::ExternalPaths, _, cx| {
                shell.enqueue_dropped_paths(paths.paths(), cx)
            }));

        let task_list = if self.task_rows.is_empty() {
            div()
                .h(px(132.))
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
            .h(px(list_height))
            .into_any_element()
        };

        ui_components::card()
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
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .text_color(rgb(ui_theme::TEXT))
                            .child("传输任务"),
                    )
                    .child(actions),
            )
            .child(drop_zone)
            .child(
                div()
                    .text_sm()
                    .font_weight(gpui::FontWeight::MEDIUM)
                    .text_color(rgb(ui_theme::TEXT))
                    .child(format!("传输列表（{} 个任务）", self.task_rows.len())),
            )
            .child(
                div()
                    .w_full()
                    .overflow_hidden()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(ui_theme::BORDER))
                    .child(task_list),
            )
    }

    fn receive_connection_bar(&self, wide: bool, cx: &Context<Self>) -> gpui::Div {
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
            .flex_col()
            .gap_2()
            .child(ui_components::field_label("接收目录（仅本机可见）"))
            .child(
                div()
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
                    )),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(if applied_differs {
                        ui_theme::WARNING
                    } else {
                        ui_theme::TEXT_SECONDARY
                    }))
                    .child(if applied_differs {
                        "目录草稿待保存；保存后仅用于新任务"
                    } else {
                        "保存接收目录的更改后，仅新任务使用新路径"
                    }),
            );
        let receive = if applied_differs {
            receive.child(Self::path_line(
                "当前任务仍使用",
                self.applied_receive_root.as_ref(),
            ))
        } else {
            receive
        };

        let (peer_label, peer_tone) = self.header_status(cx);
        let mut connection = div()
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .gap_2()
            .child(ui_components::field_label("连接状态"))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(ui_components::status_badge(peer_label, peer_tone))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .text_sm()
                            .text_color(rgb(ui_theme::TEXT_SECONDARY))
                            .child(self.network_status.clone()),
                    ),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .truncate()
                    .child(self.current_peer_label(cx)),
            );
        if let Ok(peer) = NodeId::from_hex(self.peer_id.read(cx).content.trim())
            && let Some(speed) = self.speed_views.0.get(&peer)
            && !speed.snapshot.rtt.is_zero()
        {
            connection = connection.child(
                div()
                    .text_xs()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child(format!(
                        "当前对端最近测速 RTT {:.1} ms",
                        speed.snapshot.rtt.as_secs_f64() * 1_000.
                    )),
            );
        }

        let content = div().gap_4();
        let content = if wide {
            content
                .flex()
                .items_start()
                .child(receive)
                .child(div().w(px(1.)).h(px(54.)).bg(rgb(ui_theme::BORDER)))
                .child(connection)
        } else {
            content.flex_col().child(receive).child(connection)
        };
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p(px(12.))
            .bg(rgb(ui_theme::SURFACE))
            .border_1()
            .border_color(rgb(ui_theme::BORDER))
            .rounded_xl()
            .flex_shrink_0()
            .child(content)
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

        let upload_selected = self.settings.speedtest_direction == SpeedtestDirection::Upload;
        let download_selected = !upload_selected;
        let upload_button = ui_components::secondary_button("发送", editing_enabled);
        let upload_button = if upload_selected {
            upload_button
                .bg(rgb(ui_theme::PRIMARY_SOFT))
                .border_color(rgb(ui_theme::PRIMARY))
                .text_color(rgb(ui_theme::PRIMARY))
        } else {
            upload_button
        }
        .on_mouse_up(
            MouseButton::Left,
            cx.listener(|shell, _: &MouseUpEvent, _, cx| {
                shell.set_speed_direction(SpeedtestDirection::Upload, cx)
            }),
        );
        let download_button = ui_components::secondary_button("接收", editing_enabled);
        let download_button = if download_selected {
            download_button
                .bg(rgb(ui_theme::PRIMARY_SOFT))
                .border_color(rgb(ui_theme::PRIMARY))
                .text_color(rgb(ui_theme::PRIMARY))
        } else {
            download_button
        }
        .on_mouse_up(
            MouseButton::Left,
            cx.listener(|shell, _: &MouseUpEvent, _, cx| {
                shell.set_speed_direction(SpeedtestDirection::Download, cx)
            }),
        );

        let controls = div()
            .flex()
            .items_center()
            .gap_2()
            .child(upload_button)
            .child(download_button)
            .child(
                ui_components::secondary_button(
                    format!("时长 {} 秒", self.settings.speedtest_seconds),
                    editing_enabled,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(Self::cycle_speedtest_duration),
                ),
            )
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
            .child(
                ui_components::secondary_button("取消", running).on_mouse_up(
                    MouseButton::Left,
                    cx.listener(|shell, _: &MouseUpEvent, _, cx| shell.cancel_speed_ui(cx)),
                ),
            );

        let mut result = ui_components::card()
            .child(ui_components::section_header(
                "◉",
                "直连测速",
                "测试当前已认证对端的真实直连性能",
            ))
            .child(controls);

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
            let direction = if sending {
                "本机 → 对端"
            } else {
                "对端 → 本机"
            };
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
                "无可用样本".to_owned()
            } else {
                format!("{:.1} ms", snapshot.rtt.as_secs_f64() * 1_000.)
            };
            result = result
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(ui_components::status_badge(status, status_tone))
                        .child(
                            div()
                                .text_xs()
                                .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                .child(format!("对端 {} · {direction}", peer.short())),
                        )
                        .child(ui_components::progress_bar(progress))
                        .child(
                            div()
                                .w(px(52.))
                                .text_xs()
                                .text_color(rgb(ui_theme::TEXT_SECONDARY))
                                .child(format!("{progress:.0}%")),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(ui_components::metric_tile(
                            "瞬时速度",
                            format!("{:.2} MiB/s", view.instant / 1_048_576.),
                            "当前采样",
                            ui_theme::PRIMARY_SOFT,
                        ))
                        .child(ui_components::metric_tile(
                            "平均速度",
                            format!("{:.2} Mbps", snapshot.bytes_per_second * 8. / 1_000_000.),
                            "按真实字节和耗时计算",
                            ui_theme::SURFACE_SUBTLE,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_2()
                        .text_xs()
                        .text_color(rgb(ui_theme::TEXT_SECONDARY))
                        .child(format!(
                            "实际传输 {} · 耗时 {:.2} 秒 · RTT {rtt}",
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
                    .child("等待双方授权；有文件活动时测速会明确拒绝，不会自动暂停任务"),
            );
        } else {
            result = result.child(
                div()
                    .p(px(12.))
                    .rounded_md()
                    .bg(rgb(ui_theme::SURFACE_SUBTLE))
                    .text_sm()
                    .text_color(rgb(ui_theme::TEXT_SECONDARY))
                    .child("尚未测速；测速使用已认证直连，不读取或生成文件")
                    .child(format!(
                        "当前方向：{}",
                        self.settings.speedtest_direction.label()
                    )),
            );
        }
        result
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
        card.child(
            div()
                .text_xs()
                .text_color(rgb(ui_theme::TEXT_SECONDARY))
                .child("接收目录保存后仅供新任务使用；已运行任务保留原接收目录"),
        )
    }
}

impl Focusable for DesktopShell {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for DesktopShell {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let logical_width = window.viewport_size().width / px(window.scale_factor());
        let wide_layout = logical_width >= 1040.;
        let speed_card = self.speed_test_card(cx);
        let advanced_card = self.advanced_network_card(window, cx);
        let bottom_cards = if wide_layout {
            div()
                .flex()
                .gap_3()
                .child(
                    div()
                        .flex_basis(relative(0.55))
                        .flex_grow()
                        .min_w_0()
                        .child(speed_card),
                )
                .child(
                    div()
                        .flex_basis(relative(0.45))
                        .flex_grow()
                        .min_w_0()
                        .child(advanced_card),
                )
        } else {
            div()
                .flex()
                .flex_col()
                .gap_3()
                .child(speed_card)
                .child(advanced_card)
        };

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
            .on_action(cx.listener(|shell, _: &ToggleSettings, window, cx| {
                shell.toggle_settings(window, cx)
            }))
            .on_action(
                cx.listener(|shell, _: &PauseSelected, _, cx| shell.selected_action(false, cx)),
            )
            .on_action(
                cx.listener(|shell, _: &ResumeSelected, _, cx| shell.selected_action(true, cx)),
            )
            .child(self.app_header(cx))
            .child(self.connection_card(window, cx))
            .child(self.transfer_card(cx))
            .child(self.receive_connection_bar(wide_layout, cx))
            .child(bottom_cards)
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
                ..Default::default()
            },
            move |_, cx| {
                let peer_id = cx.new(|cx| TextField::new(cx, "输入或粘贴完整的 32 位对端 ID"));
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
                cx.new(|cx| DesktopShell {
                    peer_id,
                    signal_host,
                    signal_port,
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
                    task_rows: Vec::new(),
                    expanded_groups: HashSet::new(),
                    selected_task: None,
                    queue_status: "正在载入任务…".into(),
                    speed_views: Default::default(),
                    speed_peer: None,
                    speed_request_until: None,
                    show_settings: !has_saved_network_config,
                    pending_resumes: HashMap::new(),
                    applied_receive_root: initial_receive_root,
                    task_scroll: Default::default(),
                    status: initial_status.into(),
                    focus_handle: cx.focus_handle(),
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
        marked_selection_to_utf8, mouse_index_for_layout, utf8_offset_from_utf16,
        utf16_offset_from_utf8,
    };

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
