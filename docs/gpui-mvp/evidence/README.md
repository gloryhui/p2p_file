# T001 Linux evidence

This directory contains the reviewed Linux GUI evidence for GPUI-0001/T001. The
PNG files are captured from the built `p2p-desktop` binary under Ubuntu 24.04,
Xvfb, Mesa llvmpipe, Openbox, and a D-Bus session; they are software-display
evidence, not a real-GPU or native Windows/macOS claim.

## Reproduction environment

```text
Ubuntu 24.04 x86_64
rustc 1.98.1 (48a229cea 2026-09-01)
cargo 1.98.1 (797e8a9bc 2026-08-05)
gpui = 0.2.2 (exact, Cargo.lock)
GPU: llvmpipe (LLVM 20.1.2, Mesa 25.2.8)
```

The CI source of truth for Linux build packages is
[`../../.github/workflows/gpui.yml`](../../../.github/workflows/gpui.yml) (the
relative link resolves to the repository workflow from this document). The
local runtime/evidence packages were installed with the explicitly scoped
commands below; no Cargo configuration was changed:

```sh
sudo apt-get install -y \
  libxcb1-dev libxkbcommon-dev libxkbcommon-x11-dev libx11-xcb-dev \
  libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxcb-randr0-dev
sudo apt-get install -y mesa-vulkan-drivers vulkan-tools xdotool xclip imagemagick
sudo apt-get install -y xdg-desktop-portal xdg-desktop-portal-gtk dbus-x11 openbox
```

Build and test commands run against the final layout change:

```sh
cargo fmt --all -- --check
cargo check --locked --offline --features gui --bin p2p-desktop
cargo test --locked --offline --features gui --lib desktop::tests
cargo clippy --locked --offline --features gui --all-targets -- -D warnings
cargo build --locked --offline --features gui --bin p2p-desktop
```

All five commands passed. The six explicit desktop tests cover UTF-16/UTF-8
offsets with CJK and emoji; IME selection after a multibyte prefix; stale
ASCII-to-emoji and long-to-short layouts; placeholder transitions; and valid
UTF-8 boundaries for the current layout.

## First-frame and minimum-size evidence

The first capture was intentionally retained as a diagnostic, not as a PASS:

1. With `Xvfb :99 -screen 0 1280x800x24 -nolisten tcp` and no window manager,
   `env DISPLAY=:99 ./target/debug/p2p-desktop` was started and allowed to run
   for three seconds. Window `2097153` was found and captured without a resize;
   `gpui-t001-initial-v2.png` is the resulting 960x680, 217-byte black frame.
2. Resizing that same no-WM window to 959x679 and back to 960x680, then waiting
   two seconds, caused a repaint. `gpui-t001-initial-v3.png` is retained as a
   diagnostic only; it is not the accepted first-frame proof.
3. The reproducible accepted run started the rebuilt binary in an isolated
   D-Bus session with Openbox:

   ```sh
   env DISPLAY=:99 XDG_CURRENT_DESKTOP=GNOME \
     dbus-run-session -- sh -c \
     'openbox --sm-disable >/tmp/gpui-t001-openbox.log 2>&1 & \
      exec /tmp/p2p-gpui-t001-g01/target/debug/p2p-desktop'
   ```

   After two seconds, window `4194305` was located; `xdotool windowfocus` was
   sent, one second was allowed for expose/focus, and the window was captured
   without resizing. `gpui-t001-wm-first-frame.png` is the visually inspected
   960x680 first frame. No production polling or repaint workaround was added.

4. To separate the earlier manual-focus evidence from a WM startup race, a fresh
   `:101` display started Openbox first. `xprop -root _NET_SUPPORTING_WM_CHECK`
   returned `0x20011f`; only then was the GUI started with `dbus-run-session`.
   After three seconds, window `4194305` was captured directly, with no resize
   and no `xdotool windowfocus`. The visually inspected
   [`gpui-t001-wm-ready-auto-first-frame.png`](screenshots/gpui-t001-wm-ready-auto-first-frame.png)
   is the automatic first-frame result. This confirms the no-WM black frame is
   an Xvfb/WM expose/focus environment difference, not a reason to add a
   production repaint loop.

The minimum-size run used `xdotool windowsize --sync WINDOW 760 560`. The top
view is [`gpui-t001-minimum-v2-top.png`](screenshots/gpui-t001-minimum-v2-top.png);
wheel-scrolling the root container to the bottom produced
[`gpui-t001-minimum-v2-bottom2.png`](screenshots/gpui-t001-minimum-v2-bottom2.png),
where the complete status bar is visible. The two-line source correction is
the `id("desktop-shell").overflow_y_scroll()` root container in
`src/desktop/mod.rs`.

## T001 attempt 2 disabled-control evidence

The attempt 2 build was run in a fresh D-Bus session on Xvfb display `:111`
with Openbox ready before the GUI started. The first-frame capture is
[`gpui-t001-a2-disabled-first-frame.png`](screenshots/gpui-t001-a2-disabled-first-frame.png)
at 960x680. Both `复制（无身份）` and `连接（网络未接入）` are visibly disabled;
the peer ID field remains editable.

For the no-op interaction capture,
[`gpui-t001-a2-disabled-noop.png`](screenshots/gpui-t001-a2-disabled-noop.png),
`peer-test` was entered and the disabled connection control was clicked. The
status stayed `未配置身份；网络功能待接入`; it did not report a connection.
The disabled copy control was also clicked while the X11 clipboard contained
`clipboard-sentinel`; reading the clipboard afterward returned the same value.
Neither disabled control has a mouse-up handler in the T001 shell.

At the required minimum size, the top capture
[`gpui-t001-a2-minimum-top.png`](screenshots/gpui-t001-a2-minimum-top.png)
shows both disabled controls. After scrolling to the bottom,
[`gpui-t001-a2-minimum-bottom.png`](screenshots/gpui-t001-a2-minimum-bottom.png)
shows the unchanged disconnected status bar while retaining the controls in
view. The runtime window geometry was 760x560 logical pixels.

Reproduction commands, after building the binary:

```sh
Xvfb :111 -screen 0 1280x800x24 -nolisten tcp
env DISPLAY=:111 XDG_CURRENT_DESKTOP=GNOME openbox --sm-disable
env DISPLAY=:111 xprop -root _NET_SUPPORTING_WM_CHECK
env DISPLAY=:111 XDG_CURRENT_DESKTOP=GNOME dbus-run-session -- \
  target/debug/p2p-desktop
env DISPLAY=:111 xdotool windowsize --sync WINDOW 760 560
env DISPLAY=:111 xdotool mousemove --window WINDOW 700 500 \
  click --repeat 8 --delay 100 5
```

To check the disabled copy control, keep the clipboard owner alive in a
separate terminal with `printf '%s' 'clipboard-sentinel' | xclip -quiet
-selection clipboard -i -loops 10`, click `复制（无身份）`, then run
`xclip -selection clipboard -o`; the output remains `clipboard-sentinel`.

## Input, clipboard, and native picker evidence

`xdotool` focused the peer field, typed `peer-test`, sent Ctrl-A/C, and
`xclip -selection clipboard -o` returned `peer-test`. A persistent X11
clipboard owner then supplied `非法-中文-🙂`; Ctrl-V displayed the complete
string in the GPUI field and Ctrl-A/C returned the same UTF-8 bytes. The
visually inspected result is
[`gpui-t001-utf8-paste.png`](screenshots/gpui-t001-utf8-paste.png).

With the portal packages above and the same `DISPLAY=:99` plus
`dbus-run-session`/Openbox process, GPUI 0.2.2 opened the native GTK portal
chooser (the fixed GPUI source calls `org.freedesktop.portal.FileChooser`):

- **File:** `Open File` appeared; Escape closed it and the status became
  `已取消文件选择`, with no file selected. See
  [`gpui-t001-file-picker-open.png`](screenshots/gpui-t001-file-picker-open.png)
  and [`gpui-t001-file-picker-cancel-status.png`](screenshots/gpui-t001-file-picker-cancel-status.png).
- **Send directory:** `Open Folder` appeared; Escape closed it and the status
  became `已取消目录选择`, with no directory selected. See
  [`gpui-t001-folder-picker-open.png`](screenshots/gpui-t001-folder-picker-open.png)
  and [`gpui-t001-folder-picker-cancel-status.png`](screenshots/gpui-t001-folder-picker-cancel-status.png).
- **Receive directory:** the same `Open Folder` path was exercised; Escape
  closed it and the status became `已取消接收目录选择`, with no directory
  selected. See
  [`gpui-t001-receive-picker-cancel-status.png`](screenshots/gpui-t001-receive-picker-cancel-status.png).

## Scale-factor evidence

This is an environment scale test, not a physical-DPI claim. A fresh display
and process were used:

```sh
Xvfb :100 -screen 0 1920x1200x24 -nolisten tcp
env DISPLAY=:100 GPUI_X11_SCALE_FACTOR=1.5 XDG_CURRENT_DESKTOP=GNOME \
  dbus-run-session -- sh -c \
  'openbox --sm-disable >/tmp/gpui-t001-openbox-scale.log 2>&1 & \
   exec /tmp/p2p-gpui-t001-g01/target/debug/p2p-desktop'
```

The process environment reported `GPUI_X11_SCALE_FACTOR=1.5` and the GPUI
window measured 1440x1020, i.e. 960x680 logical pixels at 150%. The visually
inspected capture is [`gpui-t001-dpi-150.png`](screenshots/gpui-t001-dpi-150.png).

## Remaining native-platform responsibility

The Windows 10 22H2 and macOS 13+ Apple Silicon smoke tests were not executed
on this Linux worker. T012 must provide those devices/VMs and record, for each,
the OS version, SDK/toolchain, native first frame, 760x560 minimum window,
Ctrl/Command-A/C/V plus CJK/emoji input, native file/folder cancellation, and
high-DPI behavior. The green Windows-2022 and macOS-14 CI jobs prove compilation
for their runner targets only; they do not replace those native smoke tests.
