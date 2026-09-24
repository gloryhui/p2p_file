//! Native GPUI desktop shell for T001.
//!
//! This module deliberately stops at platform-facing shell behaviour. It does
//! not create a node identity, open a peer connection, or pretend that a
//! transfer succeeded. Those responsibilities belong to later tasks.
//!
//! TextField and TextFieldElement are adapted from
//! gpui v0.2.2/examples/input.rs (Apache-2.0, Zed Industries, Inc.). The
//! adaptation changes the names, styling, and application wiring, and adds the
//! T001 shell state/path-picker boundaries; it is not presented as original
//! MIT-licensed application code. See docs/gpui-mvp/THIRD_PARTY_NOTICES.md.

mod config;
mod instance_lock;

use std::{ops::Range, path::PathBuf};

use crate::identity::Identity;
use config::{AppPaths, ConfigError, DesktopConfig, SettingsDraft, SpeedtestDirection};
use instance_lock::InstanceLock;

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
    ]
);

struct DesktopStartup {
    instance_lock: InstanceLock,
    identity_id: Option<String>,
    identity_status: String,
    config_file: PathBuf,
    settings: SettingsDraft,
    config_note: String,
    can_save_settings: bool,
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

        let (identity_id, identity_status) = match Identity::load_or_create(&paths.identity_file())
        {
            Ok(identity) => (
                Some(identity.node_id().to_hex()),
                "本机身份已就绪".to_owned(),
            ),
            Err(error) => (None, format!("本机身份不可用：{error}")),
        };

        let config_file = paths.config_file();
        let defaults = || SettingsDraft::defaults(paths.downloads_dir.clone());
        let (settings, config_note, can_save_settings) = match DesktopConfig::load(&config_file) {
            Ok(Some(config)) => config::restore_saved_settings(config),
            Ok(None) => {
                let note = if paths.downloads_dir.is_some() {
                    "尚未保存信令设置；请填写主机和端口".to_owned()
                } else {
                    "未找到系统 Downloads，请选择接收目录".to_owned()
                };
                (defaults(), note, true)
            }
            Err(ConfigError::Corrupt(error)) => (
                defaults(),
                format!("配置损坏，原文件已保留；保存已禁用：{error}"),
                false,
            ),
            Err(error) => (
                defaults(),
                format!("配置读取失败，保存已禁用：{error}"),
                false,
            ),
        };

        Ok(Self {
            instance_lock,
            identity_id,
            identity_status,
            config_file,
            settings,
            config_note,
            can_save_settings,
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
    identity_status: SharedString,
    config_file: PathBuf,
    config_note: SharedString,
    can_save_settings: bool,
    is_saving_settings: bool,
    _instance_lock: InstanceLock,
    status: SharedString,
    focus_handle: FocusHandle,
}

impl DesktopShell {
    fn set_status(&mut self, status: impl Into<SharedString>, cx: &mut Context<Self>) {
        self.status = status.into();
        cx.notify();
    }

    fn copy_node_id(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(identity_id) = self.identity_id.as_ref() {
            cx.write_to_clipboard(ClipboardItem::new_string(identity_id.clone()));
            self.set_status("已复制完整本机 Node ID", cx);
        }
    }

    fn cycle_concurrency(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.settings.send_concurrency = self.settings.send_concurrency % 3 + 1;
        cx.notify();
    }

    fn cycle_speedtest_duration(
        &mut self,
        _: &MouseUpEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
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
        self.settings.speedtest_direction = match self.settings.speedtest_direction {
            SpeedtestDirection::Upload => SpeedtestDirection::Download,
            SpeedtestDirection::Download => SpeedtestDirection::Upload,
        };
        cx.notify();
    }

    fn save_settings(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        if !self.can_save_settings || self.is_saving_settings {
            self.set_status("当前配置不可保存；请检查配置诊断信息", cx);
            return;
        }

        let mut draft = self.settings.clone();
        draft.signal_host = self.signal_host.read(cx).content.to_string();
        draft.signal_port = self.signal_port.read(cx).content.to_string();
        let config_file = self.config_file.clone();
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
                            shell.config_note =
                                "设置已保存；接收目录写能力检查通过；网络功能待接入".into();
                            shell.set_status("设置已保存；当前仍未连接，网络功能待接入", cx);
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
                        shell.selected_files = paths;
                        shell.set_status(format!("已选择 {count} 个文件；网络传输仍待接入"), cx);
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
                                shell.selected_folder = Some(path.to_path_buf());
                                shell.set_status(
                                    format!("已选择目录 {path_text}；网络传输仍待接入"),
                                    cx,
                                );
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
                                    "已选择新接收目录；保存时会重新验证写能力；网络功能待接入"
                                        .into();
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

    fn unavailable_control(label: &'static str) -> impl IntoElement {
        div()
            .px_2()
            .py_2()
            .bg(rgb(0xf0f2f5))
            .border_1()
            .border_color(rgb(0xd9dee7))
            .rounded_md()
            .text_color(rgb(0x737e8d))
            .cursor(CursorStyle::Arrow)
            .child(label)
    }

    fn choose_files_button(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .px_2()
            .py_2()
            .bg(rgb(0xeaf1ff))
            .border_1()
            .border_color(rgb(0xb8cdfa))
            .rounded_md()
            .text_color(rgb(0x2456a6))
            .child("选择文件")
            .hover(|style| style.bg(rgb(0xdce8ff)).cursor_pointer())
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
}

impl Focusable for DesktopShell {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for DesktopShell {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let files = if self.selected_files.is_empty() {
            vec!["尚未选择文件".to_owned()]
        } else {
            self.selected_files
                .iter()
                .map(|path| {
                    path.to_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| "路径编码不受支持".to_owned())
                })
                .collect()
        };
        let identity_text = self
            .identity_id
            .clone()
            .unwrap_or_else(|| "身份不可用".to_owned());

        div()
            .size_full()
            .id("desktop-shell")
            .overflow_y_scroll()
            .bg(rgb(0xf4f7fb))
            .flex()
            .flex_col()
            .gap_4()
            .p(px(28.))
            .text_color(rgb(0x1d2633))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(div().text_xl().child("P2P File"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(0x5f6b7a))
                                    .child("原生 GPUI 桌面壳 · T002 配置与身份"),
                            ),
                    )
                    .child(
                        div()
                            .px_2()
                            .py_1()
                            .rounded_md()
                            .bg(rgb(0xfff3d6))
                            .text_color(rgb(0x8b5a00))
                            .child("未连接 · 网络功能待接入"),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .p(px(20.))
                    .bg(white())
                    .border_1()
                    .border_color(rgb(0xdde3ee))
                    .rounded_md()
                    .shadow_sm()
                    .child(div().text_size(px(18.)).child("启动设置"))
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(div().text_sm().child("信令主机或 IP"))
                                    .child(self.signal_host.clone()),
                            )
                            .child(
                                div()
                                    .w(px(150.))
                                    .flex()
                                    .flex_col()
                                    .gap_1()
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
                            .child(
                                div()
                                    .px_2()
                                    .py_2()
                                    .bg(rgb(0xf3f5f8))
                                    .border_1()
                                    .border_color(rgb(0xdde3ee))
                                    .rounded_md()
                                    .child("选择接收目录")
                                    .hover(|style| style.bg(rgb(0xe9edf3)).cursor_pointer())
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(Self::choose_receive_directory),
                                    ),
                            )
                            .child(
                                div()
                                    .px_2()
                                    .py_2()
                                    .bg(rgb(0xf3f5f8))
                                    .border_1()
                                    .border_color(rgb(0xdde3ee))
                                    .rounded_md()
                                    .child(format!(
                                        "发送并发：{}（点击切换）",
                                        self.settings.send_concurrency
                                    ))
                                    .hover(|style| style.bg(rgb(0xe9edf3)).cursor_pointer())
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(Self::cycle_concurrency),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .items_center()
                            .child(
                                div()
                                    .px_2()
                                    .py_2()
                                    .bg(rgb(0xf3f5f8))
                                    .border_1()
                                    .border_color(rgb(0xdde3ee))
                                    .rounded_md()
                                    .child(format!(
                                        "测速时长：{} 秒（点击切换）",
                                        self.settings.speedtest_seconds
                                    ))
                                    .hover(|style| style.bg(rgb(0xe9edf3)).cursor_pointer())
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(Self::cycle_speedtest_duration),
                                    ),
                            )
                            .child(
                                div()
                                    .px_2()
                                    .py_2()
                                    .bg(rgb(0xf3f5f8))
                                    .border_1()
                                    .border_color(rgb(0xdde3ee))
                                    .rounded_md()
                                    .child(format!(
                                        "测速方向：{}（点击切换）",
                                        self.settings.speedtest_direction.label()
                                    ))
                                    .hover(|style| style.bg(rgb(0xe9edf3)).cursor_pointer())
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(Self::toggle_speedtest_direction),
                                    ),
                            )
                            .child(self.save_settings_button(cx)),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x5f6b7a))
                            .child(self.config_note.clone()),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x8b5a00))
                            .child("保存设置仅记录上线意图；网络功能待接入，不会显示在线。"),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .p(px(20.))
                    .bg(white())
                    .border_1()
                    .border_color(rgb(0xdde3ee))
                    .rounded_md()
                    .shadow_sm()
                    .child(div().text_size(px(18.)).child("建立连接"))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(0x5f6b7a))
                                    .child("本机 Node ID"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap_2()
                                    .items_center()
                                    .child(
                                        div()
                                            .flex_1()
                                            .h(px(40.))
                                            .p(px(7.))
                                            .bg(rgb(0xf3f5f8))
                                            .border_1()
                                            .border_color(rgb(0xdde3ee))
                                            .rounded_md()
                                            .text_color(rgb(0x7b8797))
                                            .truncate()
                                            .child(identity_text),
                                    )
                                    .child(self.copy_identity_button(cx)),
                            ),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x5f6b7a))
                            .child(self.identity_status.clone()),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(0x5f6b7a))
                                    .child("对端 Node ID"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .gap_2()
                                    .items_center()
                                    .child(self.peer_id.clone())
                                    .child(Self::unavailable_control("连接（网络未接入）")),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap_4()
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .p(px(20.))
                            .bg(white())
                            .border_1()
                            .border_color(rgb(0xdde3ee))
                            .rounded_md()
                            .child(div().text_size(px(18.)).child("发送"))
                            .child(
                                div()
                                    .flex()
                                    .gap_2()
                                    .items_center()
                                    .child(self.choose_files_button(cx))
                                    .child(
                                        div()
                                            .px_2()
                                            .py_2()
                                            .bg(rgb(0xeaf1ff))
                                            .border_1()
                                            .border_color(rgb(0xb8cdfa))
                                            .rounded_md()
                                            .text_color(rgb(0x2456a6))
                                            .child("选择目录")
                                            .hover(|style| style.bg(rgb(0xdce8ff)).cursor_pointer())
                                            .on_mouse_up(
                                                MouseButton::Left,
                                                cx.listener(Self::choose_folder),
                                            ),
                                    ),
                            )
                            .child(Self::path_line("发送目录", self.selected_folder.as_ref()))
                            .child(
                                div()
                                    .h(px(140.))
                                    .w_full()
                                    .id("selected-files")
                                    .overflow_y_scroll()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .children(files.into_iter().map(|path| {
                                        div()
                                            .w_full()
                                            .text_sm()
                                            .truncate()
                                            .text_color(rgb(0x5f6b7a))
                                            .child(path)
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .p(px(20.))
                            .bg(white())
                            .border_1()
                            .border_color(rgb(0xdde3ee))
                            .rounded_md()
                            .child(div().text_size(px(18.)).child("接收"))
                            .child(Self::path_line(
                                "接收目录",
                                self.settings.receive_directory.as_ref(),
                            ))
                            .child(
                                div().text_sm().text_color(rgb(0x5f6b7a)).child(
                                    "收到的文件将在后续任务中落盘；当前不会写入任何传输数据。",
                                ),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .p(px(14.))
                    .bg(rgb(0xeaf1ff))
                    .border_1()
                    .border_color(rgb(0xc6d8ff))
                    .rounded_md()
                    .child(div().text_color(rgb(0x2456a6)).child("状态"))
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
        ]);

        let bounds = Bounds::centered(None, size(px(960.), px(680.)), cx);
        let DesktopStartup {
            instance_lock,
            identity_id,
            identity_status,
            config_file,
            settings,
            config_note,
            can_save_settings,
        } = startup;
        let initial_status = if identity_id.is_some() {
            if settings.signal_host.is_empty() {
                "未配置信令；网络功能待接入"
            } else {
                "未连接；网络功能待接入"
            }
        } else {
            &identity_status
        }
        .to_owned();
        let initial_host = settings.signal_host.clone();
        let initial_port = settings.signal_port.clone();
        let window = cx.open_window(
            WindowOptions {
                titlebar: Some(gpui::TitlebarOptions {
                    title: Some("P2P File — GPUI".into()),
                    ..Default::default()
                }),
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(760.), px(560.))),
                ..Default::default()
            },
            move |_, cx| {
                let peer_id = cx.new(|cx| TextField::new(cx, "输入或粘贴对端 ID（仅壳层输入）"));
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
                    identity_status: identity_status.into(),
                    config_file,
                    config_note: config_note.into(),
                    can_save_settings,
                    is_saving_settings: false,
                    _instance_lock: instance_lock,
                    status: initial_status.into(),
                    focus_handle: cx.focus_handle(),
                })
            },
        );

        match window {
            Ok(window) => {
                window
                    .update(cx, |shell, window, cx| {
                        window.focus(&shell.signal_host.focus_handle(cx));
                        cx.activate(true);
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
