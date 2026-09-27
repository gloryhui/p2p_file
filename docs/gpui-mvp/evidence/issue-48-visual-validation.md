# Issue #48 visual validation

## Screenshot provenance

All new captures are real renders of the GPUI 0.2.2 desktop binary on Ubuntu 24.04.5 LTS with X11, Xvfb, Openbox, and Mesa software rendering. Each screenshot is committed as an image under this directory's `screenshots/` folder.

| Screenshot | State and capture conditions |
| --- | --- |
| `ui-redesign-before.png` | Unmodified `origin/main` at `c52516bd6a074c425a23548e0f82c163e5fa9086`, 960×680 logical pixels. |
| `ui-redesign-after.png` | This branch's desktop binary with a fresh isolated config, at 1180×780 logical pixels. |
| `ui-redesign-main-connected.png` | Two app instances with distinct generated identities connected through a local signal server; the peer shown is authenticated. 1180×780. |
| `ui-redesign-main-transfer-running.png` | A real 256 MiB random file sent between those connected instances. Captured during transfer at 48.5% (124.25 MiB confirmed, 11.91 MiB/s in the UI). |
| `ui-redesign-main-min-760x560.png` | The connected window resized to 760×560; the client window geometry was checked at exactly that size. Content remains vertically scrollable and the lower cards stack. |
| `ui-redesign-speed-running.png` | The connected peer's real 30-second upload speed test, captured while it showed “测速中” and 57% progress. |
| `ui-redesign-settings-edit.png` | Advanced network settings expanded with the saved local signal host and port loaded into editable fields; no settings were saved during capture. |
| `ui-redesign-main-150dpi.png` | GPUI scale factor 1.5 via X11 `Xft.dpi=144`; logical window 1180×780, physical capture 1770×1170. |
| `ui-redesign-main-ubuntu.png` | Ubuntu 24.04.5 LTS, X11/Xvfb/Openbox, 1180×780; authenticated peer and a real completed transfer are visible. |

The sent and received 256 MiB files had the same SHA-256:
`fc69cc5b6523e3e54c33aaad8511952aaaebcd4a90776ae6d5c13432e030bb76`.

Windows and macOS screenshots are not included. This change was implemented and visually exercised in a Linux-only workspace; the Windows and macOS GitHub Actions runners build and test native binaries but do not provide an interactive desktop session in the existing workflow. No Linux image is presented as a Windows or macOS capture.

## Reference elements intentionally not reproduced

The supplied image is a visual reference only. The current desktop backend and persisted settings do not provide the following values or actions, so the UI does not invent them:

- NAT type, public/local UDP mappings, packet loss, jitter, or a network-quality rating.
- UDP port, relay, and automatic-reconnect switches.
- Simultaneous bidirectional speed testing. The existing speed-test API supports upload or download, so the redesigned controls expose only those real directions.
- A task-list clear action or an “open received file” action. The current task UI contract exposes selection, pause, and continue; the redesign keeps the available task actions.

The connection summary shows the current signaling/peer lifecycle, authenticated peer, and an RTT only when the session supplies a nonzero sample. Advanced settings expose the existing signal endpoint and transfer concurrency settings, not settings that the backend does not persist.

Separate Linux X11 smoke renders at 125% and 200% (`GPUI_X11_SCALE_FACTOR=1.25` and `2.0`) were visually inspected for clipping; the app opened at the expected 1.25× and 2× physical window sizes. These temporary captures are not committed. They do not substitute for native Windows/macOS GUI validation.

The isolated Xvfb session had no `xdg-desktop-portal` service or interactive Chinese IME, so native file/folder picker and IME behavior were not exercised here. File transfer itself was exercised through GPUI's external-path drop event; the existing picker prompt and keyboard bindings remain in place. Native picker, IME, and clipboard behavior still need a user-session check on the Windows/macOS desktops.
