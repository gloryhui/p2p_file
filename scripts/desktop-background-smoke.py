#!/usr/bin/env python3
"""Linux X11 native window/tray smoke, in an isolated D-Bus/Xvfb session.

dbus-run-session -- /usr/bin/python3 scripts/desktop-background-smoke.py \
    --binary /absolute/path/p2p-desktop --output /tmp/new-background-evidence

Requires python3-dbus, python3-gi, Xvfb, openbox, xdotool and xwininfo.
The mock SNI host verifies native application lifecycle, not a desktop's icon
rendering, real macOS/Windows menus, login, public networking or throughput.
"""
import argparse
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time


def wait_for(predicate, seconds=15):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        result = predicate()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError("timed out waiting for native state")


def watcher():
    import dbus
    import dbus.service
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    name = dbus.service.BusName("org.kde.StatusNotifierWatcher", bus)

    class Watcher(dbus.service.Object):
        items = []

        @dbus.service.method("org.kde.StatusNotifierWatcher", in_signature="s")
        def RegisterStatusNotifierItem(self, service):
            self.items.append(str(service) + "/StatusNotifierItem")
            self.StatusNotifierItemRegistered(self.items[-1])

        @dbus.service.signal("org.kde.StatusNotifierWatcher", signature="s")
        def StatusNotifierItemRegistered(self, item):
            pass

        @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
        def Get(self, interface, key):
            return self.GetAll(interface)[key]

        @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
        def GetAll(self, interface):
            return {"IsStatusNotifierHostRegistered": dbus.Boolean(True),
                    "RegisteredStatusNotifierItems": dbus.Array(self.items, signature="s"),
                    "ProtocolVersion": dbus.Int32(0)}

    server = Watcher(bus, "/StatusNotifierWatcher")
    GLib.MainLoop().run()
    del server, name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--diagnostics-preview", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    repo = Path(__file__).resolve().parent.parent
    if output == repo or repo in output.parents:
        parser.error("evidence must be outside the checkout")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("evidence directory must be empty")
    import dbus
    bus = dbus.SessionBus()
    if bus.name_has_owner("org.kde.StatusNotifierWatcher"):
        parser.error("run in an isolated dbus-run-session")
    env = dict(os.environ)
    for key, folder in [("XDG_CONFIG_HOME", "config"), ("XDG_DATA_HOME", "data"), ("XDG_CACHE_HOME", "cache")]:
        env[key] = str(output / folder)
    env.pop("WAYLAND_DISPLAY", None)
    env["WINIT_UNIX_BACKEND"] = "x11"
    processes = []
    logs = []
    proofs = []

    def launch(command, label):
        log = (output / (label + ".log")).open("w")
        logs.append(log)
        proc = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        processes.append(proc)
        return proc

    def command(*parts):
        return subprocess.check_output(parts, env=env, text=True, stderr=subprocess.DEVNULL).strip()

    def mapped(window):
        return "Map State: IsViewable" in command("xwininfo", "-id", window)

    def names():
        return [name for name in bus.list_names() if name.startswith("org.kde.StatusNotifierItem-")]

    try:
        read_fd, write_fd = os.pipe()
        xvfb = subprocess.Popen(["Xvfb", "-displayfd", str(write_fd), "-screen", "0", "1440x1000x24"], pass_fds=[write_fd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(xvfb)
        os.close(write_fd)
        if not select.select([read_fd], [], [], 10)[0]:
            raise AssertionError("Xvfb did not start")
        env["DISPLAY"] = ":" + os.read(read_fd, 128).decode().strip()
        os.close(read_fd)
        launch(["openbox"], "window-manager")
        host = launch([sys.executable, str(Path(__file__).resolve()), "--watcher"], "mock-host")
        wait_for(lambda: bus.name_has_owner("org.kde.StatusNotifierWatcher"))
        root = output / "config/p2p_file"
        root.mkdir(parents=True)
        receive = output / "Downloads"
        receive.mkdir()
        settings = root / "settings.json"
        settings.write_text(json.dumps({"schema_version": 6, "signal": {"host": "127.0.0.1", "port": 9},
            "receive_directory": str(receive), "send_concurrency": 1, "speedtest_seconds": 30,
            "speedtest_direction": "both", "background": {"close_to_tray": True, "launch_at_login": False}}))
        app = launch([str(binary)], "desktop")
        def main_window(visible=True):
            result = subprocess.run(["xdotool", "search"] + (["--onlyvisible"] if visible else []) + ["--pid", str(app.pid), "--name", "P2P File"], env=env, capture_output=True, text=True)
            return result.stdout.strip().splitlines()[0] if result.returncode == 0 else None
        window = wait_for(main_window)
        tray_name = wait_for(lambda: names() and names()[0])
        item = bus.get_object(tray_name, "/StatusNotifierItem")
        wait_for(lambda: any(state in str(item.Get("org.kde.StatusNotifierItem", "Title", dbus_interface="org.freedesktop.DBus.Properties")) for state in ["连接中", "需要处理", "在线"]))
        menu_path = item.Get("org.kde.StatusNotifierItem", "Menu", dbus_interface="org.freedesktop.DBus.Properties")
        menu = bus.get_object(tray_name, str(menu_path))
        def action(label):
            _, layout = menu.GetLayout(0, -1, dbus.Array([], signature="s"), dbus_interface="com.canonical.dbusmenu")
            node = next(node for node in layout[2] if node[1].get("label") == label)
            menu.Event(node[0], "clicked", dbus.String(""), dbus.UInt32(0), dbus_interface="com.canonical.dbusmenu")
        command("xdotool", "windowactivate", "--sync", window)
        (output / "main-window-properties.txt").write_text(command("xprop", "-id", window))
        if shutil.which("import"):
            # This fresh fixture starts on the first-password settings page.
            geometry = dict(line.split("=", 1) for line in command("xdotool", "getwindowgeometry", "--shell", window).splitlines())
            command("xdotool", "mousemove", "--window", window, str(int(geometry["WIDTH"]) - 80), "48")
            command("xdotool", "click", "1")
            time.sleep(0.3)
            command("import", "-window", window, str(output / "main-window.png"))
            if args.diagnostics_preview:
                command("xdotool", "mousemove", "--window", window, str(int(geometry["WIDTH"]) - 140), "48")
                command("xdotool", "click", "1")
                time.sleep(0.3)
                command("import", "-window", window, str(output / "connection-diagnostics.png"))
        command("xdotool", "key", "alt+F4")
        wait_for(lambda: not mapped(window))
        assert app.poll() is None
        proofs.append("close_hides_native_window_and_keeps_process_and_tray_alive")
        item.Activate(0, 0, dbus_interface="org.kde.StatusNotifierItem")
        wait_for(lambda: mapped(window))
        proofs.append("tray_reopens_the_same_native_window")
        action("状态面板")
        def panel_windows():
            result = subprocess.run(["xdotool", "search", "--onlyvisible", "--pid", str(app.pid)], env=env, capture_output=True, text=True)
            return [w for w in result.stdout.splitlines() if w != window]
        panel = wait_for(lambda: panel_windows())
        if shutil.which("import"):
            time.sleep(0.5)
            command("import", "-window", panel[0], str(output / "status-panel.png"))
        proofs.append("status_panel_opens_without_a_second_desktop_process")
        # Closing the panel must preserve the main window and runtime.
        command("xdotool", "windowactivate", "--sync", window)
        wait_for(lambda: not panel_windows())
        action("状态面板")
        wait_for(lambda: panel_windows())
        proofs.append("status_panel_dismisses_on_blur_and_reopens")
        item.Activate(0, 0, dbus_interface="org.kde.StatusNotifierItem")
        wait_for(lambda: mapped(window))
        command("xdotool", "windowactivate", "--sync", window)
        command("xdotool", "key", "alt+F4")
        wait_for(lambda: not mapped(window))
        host.terminate()
        host.wait(timeout=5)
        wait_for(lambda: mapped(window))
        assert app.poll() is None
        proofs.append("tray_host_loss_restores_the_hidden_main_window")
        command("xdotool", "windowactivate", "--sync", window)
        command("xdotool", "key", "ctrl+q")
        assert app.wait(timeout=15) == 0
        proofs.append("explicit_quit_finishes_structured_shutdown")
        # Reuse only the isolated app data. A configured login launch without
        # a tray host must stay visible; no user startup entries are installed.
        saved = json.loads(settings.read_text())
        saved["background"]["launch_at_login"] = True
        settings.write_text(json.dumps(saved))
        app = launch([str(binary), "--background"], "desktop-no-host")
        window = wait_for(main_window)
        time.sleep(2)
        assert mapped(window) and app.poll() is None
        proofs.append("background_login_without_tray_stays_visible")
        command("xdotool", "windowactivate", "--sync", window)
        command("xdotool", "key", "ctrl+q")
        assert app.wait(timeout=15) == 0
        # Once a usable host is ready, a saved login launch keeps the main
        # window hidden and exposes a live native entry point.
        host = launch([sys.executable, str(Path(__file__).resolve()), "--watcher"], "mock-host-login")
        wait_for(lambda: bus.name_has_owner("org.kde.StatusNotifierWatcher"))
        app = launch([str(binary), "--background"], "desktop-login")
        window = wait_for(lambda: main_window(False))
        tray_name = wait_for(lambda: names() and names()[0])
        item = bus.get_object(tray_name, "/StatusNotifierItem")
        wait_for(lambda: any(state in str(item.Get("org.kde.StatusNotifierItem", "Title", dbus_interface="org.freedesktop.DBus.Properties")) for state in ["连接中", "需要处理", "在线"]))
        assert not mapped(window) and app.poll() is None
        item.Activate(0, 0, dbus_interface="org.kde.StatusNotifierItem")
        wait_for(lambda: mapped(window))
        proofs.append("configured_login_with_tray_starts_hidden_and_can_be_reopened")
        command("xdotool", "windowactivate", "--sync", window)
        command("xdotool", "key", "ctrl+q")
        assert app.wait(timeout=15) == 0
        print(json.dumps({"result": "passed", "proofs": proofs}, ensure_ascii=False))
        (output / "result.json").write_text(json.dumps({"result": "passed", "proofs": proofs}, indent=2))
    finally:
        for proc in reversed(processes):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        for log in logs:
            log.close()


if __name__ == "__main__":
    if sys.argv[1:] == ["--watcher"]:
        watcher()
    else:
        main()
