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
mod ui_model;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use std::{ops::Range, path::PathBuf};

use crate::identity::{Identity, NodeId};
use config::{AppPaths, ConfigError, DesktopConfig, SettingsDraft, SpeedtestDirection};
use instance_lock::InstanceLock;
use task_store::TaskStore;

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
                    rgb(0x3468d4),
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
            let mut connected = self
                .peer_states
                .iter()
                .filter_map(|(p, s)| {
                    matches!(s, network_state::PeerLifecycle::Connected).then_some(p.to_hex())
                })
                .collect::<Vec<_>>();
            connected.sort();
            return if connected.is_empty() {
                "等待输入对端 ID；接收端无需预先填写发送者 ID".into()
            } else {
                format!("已认证直连：{}；可被动接收", connected.join("、"))
            };
        };
        let state = match self.peer_states.get(&peer) {
            Some(network_state::PeerLifecycle::Connected) => "已认证直连".to_owned(),
            Some(network_state::PeerLifecycle::PeerPending) => "等待对端上线".into(),
            Some(network_state::PeerLifecycle::Punching) => "正在建立直连".into(),
            Some(network_state::PeerLifecycle::Authenticating) => "正在核对身份".into(),
            Some(network_state::PeerLifecycle::Negotiating) => "正在核对版本".into(),
            Some(network_state::PeerLifecycle::Disconnected) => "连接已断开".into(),
            Some(network_state::PeerLifecycle::Failed(e)) => format!("连接失败：{e}"),
            None => "尚未连接".into(),
        };
        format!("对端 {}：{state}", peer.to_hex())
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
                    .h(px(82.))
                    .p_2()
                    .border_b_1()
                    .border_color(rgb(0xdde3ee))
                    .bg(rgb(0xeaf1ff))
                    .child(format!(
                        "{} {}",
                        if expanded { "▾" } else { "▸" },
                        group.label()
                    ))
                    .cursor_pointer()
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
            ui_model::ListRow::Task(t) => {
                let id = t.id.clone();
                let select = id.clone();
                let pause = id.clone();
                let resume = id.clone();
                let can_pause = t.can_pause();
                let can_continue = t.can_continue();
                let direction = if t.direction == task_model::TaskDirection::Send {
                    "发送"
                } else {
                    "接收"
                };
                let diagnostic = t
                    .diagnostic
                    .unwrap_or("已校验进度；异常退出后可能回退到已持久化进度");
                div()
                    .h(px(82.))
                    .p_2()
                    .border_b_1()
                    .border_color(rgb(0xdde3ee))
                    .bg(if self.selected_task.as_ref() == Some(&id) {
                        rgb(0xeaf1ff)
                    } else {
                        rgb(0xffffff)
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
                            .flex()
                            .gap_2()
                            .items_center()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .truncate()
                                    .child(format!("{} · {direction}", t.name)),
                            )
                            .child(div().text_sm().child(format!(
                                "{:.1}% · {:.2} MiB/s",
                                t.percent(),
                                t.rate / 1048576.
                            )))
                            .child(Self::control("暂停", can_pause).on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                    shell.task_action(pause.clone(), false, cx);
                                }),
                            ))
                            .child(Self::control("继续", can_continue).on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |shell, _: &MouseUpEvent, _, cx| {
                                    shell.task_action(resume.clone(), true, cx);
                                }),
                            )),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(0x5f6b7a))
                            .truncate()
                            .child(format!(
                                "{} · 对端 {} · {} / {} 字节",
                                t.state_label(),
                                t.peer.to_hex(),
                                t.confirmed,
                                t.total
                            )),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(0x8b5a00))
                            .truncate()
                            .child(diagnostic),
                    )
            }
        }
    }
    fn control(label: impl Into<SharedString>, enabled: bool) -> gpui::Div {
        div()
            .px_2()
            .py_1()
            .rounded_md()
            .border_1()
            .border_color(rgb(0xdde3ee))
            .text_sm()
            .bg(if enabled {
                rgb(0xeaf1ff)
            } else {
                rgb(0xf0f2f5)
            })
            .text_color(if enabled {
                rgb(0x2456a6)
            } else {
                rgb(0x737e8d)
            })
            .cursor(if enabled {
                CursorStyle::PointingHand
            } else {
                CursorStyle::Arrow
            })
            .child(label.into())
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

    fn toggle_speedtest_direction(
        &mut self,
        _: &MouseUpEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.change_direction(cx);
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

    fn choose_files_button(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let enabled = NodeId::from_hex(self.peer_id.read(cx).content.trim())
            .ok()
            .is_some_and(|p| {
                matches!(
                    self.peer_states.get(&p),
                    Some(network_state::PeerLifecycle::Connected)
                )
            })
            && !self
                .speed_views
                .0
                .values()
                .any(|v| v.snapshot.status == speed::SpeedStatus::Running);
        Self::control("选择文件", enabled)
            .on_mouse_up(MouseButton::Left, cx.listener(Self::choose_files))
    }

    fn path_line(label: &str, path: Option<&PathBuf>) -> impl IntoElement {
        let value = path
            .map(|path| {
                path.to_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| "路径编码不受支持".to_owned())
            })
            .unwrap_or_else(|| "尚未选择".to_owned());
        div()
            .flex()
            .gap_2()
            .text_sm()
            .child(format!("{label}："))
            .child(
                div()
                    .flex_1()
                    .truncate()
                    .text_color(rgb(0x5f6b7a))
                    .child(value),
            )
    }

    fn copy_identity_button(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let button = div().px_2().py_2().border_1().rounded_md();
        if self.identity_id.is_some() {
            button
                .bg(rgb(0xeaf1ff))
                .border_color(rgb(0xb8cdfa))
                .text_color(rgb(0x2456a6))
                .child("复制完整 ID")
                .hover(|style| style.bg(rgb(0xdce8ff)).cursor_pointer())
                .on_mouse_up(MouseButton::Left, cx.listener(Self::copy_node_id))
        } else {
            button
                .bg(rgb(0xf0f2f5))
                .border_color(rgb(0xd9dee7))
                .text_color(rgb(0x737e8d))
                .cursor(CursorStyle::Arrow)
                .child("复制（身份不可用）")
        }
    }

    fn save_settings_button(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let label = if self.is_saving_settings {
            "正在保存…"
        } else {
            "保存设置"
        };
        let button = div().px_3().py_2().border_1().rounded_md();
        if self.can_save_settings && !self.is_saving_settings {
            button
                .bg(rgb(0x2456a6))
                .border_color(rgb(0x2456a6))
                .text_color(white())
                .child(label)
                .hover(|style| style.bg(rgb(0x1d478c)).cursor_pointer())
                .on_mouse_up(MouseButton::Left, cx.listener(Self::save_settings))
        } else {
            button
                .bg(rgb(0xf0f2f5))
                .border_color(rgb(0xd9dee7))
                .text_color(rgb(0x737e8d))
                .cursor(CursorStyle::Arrow)
                .child(if self.can_save_settings {
                    label
                } else {
                    "保存已禁用"
                })
        }
    }

    fn connect_peer_button(&self, cx: &mut Context<Self>) -> impl IntoElement {
        if self.identity.is_some() && self.network_session.is_some() {
            div()
                .px_3()
                .py_2()
                .bg(rgb(0x2456a6))
                .border_1()
                .border_color(rgb(0x2456a6))
                .rounded_md()
                .text_color(white())
                .child("连接")
                .hover(|style| style.bg(rgb(0x1d478c)).cursor_pointer())
                .on_mouse_up(MouseButton::Left, cx.listener(Self::connect_peer))
        } else {
            div()
                .px_2()
                .py_2()
                .bg(rgb(0xf0f2f5))
                .border_1()
                .border_color(rgb(0xd9dee7))
                .rounded_md()
                .text_color(rgb(0x737e8d))
                .cursor(CursorStyle::Arrow)
                .child("先保存信令配置")
        }
    }
}

impl Focusable for DesktopShell {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for DesktopShell {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let identity = self
            .identity_id
            .clone()
            .unwrap_or_else(|| "身份不可用".into());
        let connected = NodeId::from_hex(self.peer_id.read(cx).content.trim())
            .ok()
            .is_some_and(|p| {
                matches!(
                    self.peer_states.get(&p),
                    Some(network_state::PeerLifecycle::Connected)
                )
            });
        let running = self
            .speed_views
            .0
            .values()
            .any(|v| v.snapshot.status == speed::SpeedStatus::Running);
        let can_start = connected && !running && self.speed_request_until.is_none();
        let speed_text=self.displayed_speed().map(|(peer,v)|{
            let s=&v.snapshot;let sending=match s.direction {protocol::SpeedDirection::Upload=>self.identity.as_ref().is_some_and(|i|i.node_id()==s.owner),protocol::SpeedDirection::Download=>self.identity.as_ref().is_some_and(|i|i.node_id()!=s.owner)};
            let status=match s.status{speed::SpeedStatus::Running=>"测速中",speed::SpeedStatus::Completed=>"已完成",speed::SpeedStatus::Cancelled=>"已取消",speed::SpeedStatus::Interrupted=>"已中断"};
            let progress=(s.elapsed.as_secs_f64()/f64::from(s.seconds)*100.).min(100.);
            format!("{} · {status} · 对端 {} · {progress:.1}%\n瞬时 {:.2} MiB/s · 平均 {:.2} Mbps · {} 字节 · 实际 {:.2} 秒 · RTT {:.1} ms",if sending{"本机 → 对端"}else{"对端 → 本机"},peer.to_hex(),v.instant/1048576.,s.bytes_per_second*8./1000000.,s.bytes,s.elapsed.as_secs_f64(),s.rtt.as_secs_f64()*1000.)
        }).unwrap_or_else(||if self.speed_request_until.is_some(){"等待双方授权；文件活动会明确拒绝测速".into()}else{"尚未测速；使用已认证直连，不读取或生成文件".into()});
        let speed_text = if self.speed_request_until.is_some() && !running {
            format!("等待双方授权；文件活动会明确拒绝测速\n上次结果：{speed_text}")
        } else {
            speed_text
        };
        let root = div()
            .size_full()
            .id("desktop-shell")
            .key_context("DesktopShell")
            .track_focus(&self.focus_handle)
            .overflow_y_scroll()
            .bg(rgb(0xf4f7fb))
            .flex()
            .flex_col()
            .gap_2()
            .p_4()
            .text_color(rgb(0x1d2633))
            .on_action(cx.listener(|s, _: &NextTask, _, cx| s.select_task(false, cx)))
            .on_action(cx.listener(|s, _: &PreviousTask, _, cx| s.select_task(true, cx)))
            .on_action(cx.listener(|s, _: &ExpandGroups, _, cx| s.expand_groups(cx)))
            .on_action(
                cx.listener(|s, _: &ChooseReceiveDirectory, _, cx| s.pick_receive_directory(cx)),
            )
            .on_action(cx.listener(|s, _: &CycleDirection, _, cx| s.change_direction(cx)))
            .on_action(cx.listener(|s, _: &CycleDuration, _, cx| s.change_duration(cx)))
            .on_action(cx.listener(|s, _: &CycleConcurrency, _, cx| s.change_concurrency(cx)))
            .on_action(cx.listener(|s, _: &NextField, w, cx| s.focus_field(false, w, cx)))
            .on_action(cx.listener(|s, _: &PreviousField, w, cx| s.focus_field(true, w, cx)))
            .on_action(cx.listener(|s, _: &CopyIdentity, _, cx| {
                if let Some(id) = &s.identity_id {
                    cx.write_to_clipboard(ClipboardItem::new_string(id.clone()));
                    s.set_status("已复制完整本机 ID", cx);
                }
            }))
            .on_action(cx.listener(|s, _: &ConnectPeer, _, cx| s.connect_current_peer(cx)))
            .on_action(cx.listener(|s, _: &ChooseFiles, _, cx| s.pick_files(cx)))
            .on_action(cx.listener(|s, _: &ChooseFolder, _, cx| s.pick_folder(cx)))
            .on_action(cx.listener(|s, _: &SaveSettings, _, cx| s.persist_settings(cx)))
            .on_action(cx.listener(|s, _: &StartSpeed, _, cx| s.start_speed_ui(cx)))
            .on_action(cx.listener(|s, _: &CancelSpeed, _, cx| s.cancel_speed_ui(cx)))
            .on_action(cx.listener(|s, _: &ToggleSettings, w, cx| s.toggle_settings(w, cx)))
            .on_action(cx.listener(|s, _: &PauseSelected, _, cx| s.selected_action(false, cx)))
            .on_action(cx.listener(|s, _: &ResumeSelected, _, cx| s.selected_action(true, cx)))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(div().text_xl().child("P2P File"))
                    .child(
                        div()
                            .text_sm()
                            .child(format!("信令：{}", self.network_status)),
                    )
                    .child(
                        Self::control(
                            if self.show_settings {
                                "收起设置"
                            } else {
                                "设置"
                            },
                            true,
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(|s, _: &MouseUpEvent, w, cx| s.toggle_settings(w, cx)),
                        ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(div().text_sm().child("本机 ID"))
                    .child(div().flex_1().text_sm().child(identity))
                    .child(self.copy_identity_button(cx)),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .items_center()
                    .child(div().text_sm().child("对端 ID"))
                    .child(div().flex_1().min_w_0().child(self.peer_id.clone()))
                    .child(self.connect_peer_button(cx)),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(0x5f6b7a))
                    .child(self.current_peer_label(cx)),
            );
        let root = if self.show_settings {
            root.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .p_3()
                        .bg(white())
                        .border_1()
                        .border_color(rgb(0xdde3ee))
                        .rounded_md()
                        .flex_shrink_0()
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .child(div().text_sm().child("信令主机/IP"))
                                        .child(self.signal_host.clone()),
                                )
                                .child(
                                    div()
                                        .w(px(110.))
                                        .child(div().text_sm().child("端口"))
                                        .child(self.signal_port.clone()),
                                ),
                        )
                        .child(Self::path_line(
                            "接收目录（仅本机可见）",
                            self.settings.receive_directory.as_ref(),
                        ))
                        .child(
                            div()
                                .flex()
                                .gap_2()
                                .items_center()
                                .child(Self::control("选择接收目录", true).on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(Self::choose_receive_directory),
                                ))
                                .child(self.save_settings_button(cx)),
                        )
                        .child(div().text_xs().child(self.config_note.clone()))
                        .child(div().text_xs().child(self.identity_status.clone())).child(div().text_xs().child("Ctrl/⌘：Shift+D 接收目录 · Shift+C 复制 ID · N 并发 · D 测速方向 · L 测速时长 · Tab 切换输入框"))
                        .child(div().text_xs().text_color(rgb(0x8b5a00)).child(
                            "可信设备 MVP：知道 ID 的节点可发送文件。保存新目录仅影响新任务。",
                        )),
                )
        } else {
            root
        };
        root.child(
            div().flex().flex_col().gap_2().p_3().bg(white()).border_1().border_color(rgb(0xdde3ee)).rounded_md().flex_shrink_0()
            .child(div().flex().justify_between().items_center().child(div().child("文件传输")).child(div().text_xs().child(self.queue_status.clone())))
            .child(div().flex().gap_2().items_center().child(self.choose_files_button(cx)).child(Self::control("选择目录",connected&&!running).on_mouse_up(MouseButton::Left,cx.listener(Self::choose_folder))).child(Self::control(format!("同时发送：{}（保存后生效）",self.settings.send_concurrency),!self.is_saving_settings).on_mouse_up(MouseButton::Left,cx.listener(Self::cycle_concurrency))).child(self.save_settings_button(cx)))
            .child(if self.task_rows.is_empty(){div().h(px(160.)).flex().items_center().justify_center().text_sm().text_color(rgb(0x5f6b7a)).child("暂无任务。选择文件或目录发送；收到的新任务会自动显示。").into_any_element()}else{gpui::uniform_list("transfer-tasks",self.task_rows.len(),cx.processor(|s,range: Range<usize>,_,cx|{let end=range.end.min(s.task_rows.len());(range.start.min(end)..end).map(|index|s.task_row(index,cx)).collect::<Vec<_>>()})).track_scroll(self.task_scroll.clone())
                            .h(px(220.)).into_any_element()})
        ).child(
            div().flex().flex_col().gap_2().p_3().bg(white()).border_1().border_color(rgb(0xdde3ee)).rounded_md().flex_shrink_0()
            .child(div().child("直连测速"))
            .child(div().flex().gap_2().items_center().child(Self::control(format!("方向：{}",self.settings.speedtest_direction.label()),!self.is_saving_settings).on_mouse_up(MouseButton::Left,cx.listener(Self::toggle_speedtest_direction))).child(Self::control(format!("时长：{} 秒",self.settings.speedtest_seconds),!self.is_saving_settings).on_mouse_up(MouseButton::Left,cx.listener(Self::cycle_speedtest_duration))).child(Self::control(if self.speed_request_until.is_some(){"等待授权…"}else{"开始"},can_start).on_mouse_up(MouseButton::Left,cx.listener(|s,_:&MouseUpEvent,_,cx|s.start_speed_ui(cx)))).child(Self::control("取消",running).on_mouse_up(MouseButton::Left,cx.listener(|s,_:&MouseUpEvent,_,cx|s.cancel_speed_ui(cx)))))
            .child(div().text_sm().child(speed_text))
        ).child(Self::path_line("新任务接收目录",self.applied_receive_root.as_ref()))
        .child(div().p_2().bg(rgb(0xeaf1ff)).text_sm().child(self.status.clone()))
        .child(div().text_xs().text_color(rgb(0x5f6b7a)).child("快捷键 Ctrl/⌘：Enter 连接 · O 文件 · Shift+O 目录 · S 保存 · T 测速 · Shift+T 取消 · ↑/↓ 选择任务 · E 展开目录 · P 暂停 · R 继续 · , 设置"))
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

        let bounds = Bounds::centered(None, size(px(960.), px(680.)), cx);
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
