#!/usr/bin/env python3
"""Verify native XDG delivery and activation on a fresh isolated D-Bus session.

No real desktop notification is sent. Invoke through dbus-run-session.
"""
import argparse
import json
import os
import select
from pathlib import Path
import subprocess
import sys
import time

def host(output):
    import dbus
    import dbus.service
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    name = dbus.service.BusName('org.freedesktop.Notifications', bus)
    class Notifications(dbus.service.Object):
        @dbus.service.method('org.freedesktop.Notifications', out_signature='ssss')
        def GetServerInformation(self):
            return ('P2P fixture', 'p2p_file tests', '1', '1.2')
        @dbus.service.method('org.freedesktop.Notifications', out_signature='as')
        def GetCapabilities(self):
            return ['actions', 'body']
        @dbus.service.method('org.freedesktop.Notifications', in_signature='susssasa{sv}i', out_signature='u')
        def Notify(self, app, replaces, icon, summary, body, actions, hints, timeout):
            payload = {'app': str(app), 'summary': str(summary), 'body': str(body),
                       'actions': list(map(str, actions)), 'timeout': int(timeout)}
            Path(output).write_text(json.dumps(payload, ensure_ascii=False))
            GLib.timeout_add(500, self.activate)
            return dbus.UInt32(7)
        @dbus.service.signal('org.freedesktop.Notifications', signature='us')
        def ActionInvoked(self, notification_id, action):
            pass
        def activate(self):
            self.ActionInvoked(7, 'default')
            return False
        @dbus.service.method('org.freedesktop.Notifications', in_signature='u')
        def CloseNotification(self, notification_id):
            pass
    service = Notifications(bus, '/org/freedesktop/Notifications')
    print('READY', flush=True)
    GLib.MainLoop().run()
    del service, name

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    import dbus
    bus = dbus.SessionBus()
    if bus.name_has_owner('org.freedesktop.Notifications'):
        parser.error('requires a fresh dbus-run-session, not a live notification service')
    repo = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    if output == repo or repo in output.parents or output.exists():
        parser.error('output must be a new path outside the checkout')
    output.parent.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--host', str(output)], stdout=subprocess.PIPE, text=True)
    try:
        if not select.select([process.stdout], [], [], 10)[0] or process.stdout.readline().strip() != 'READY':
            raise RuntimeError('mock service did not initialize')
        until = time.monotonic() + 10
        while not bus.name_has_owner('org.freedesktop.Notifications'):
            if process.poll() is not None or time.monotonic() >= until:
                raise RuntimeError('mock service not ready')
            time.sleep(.05)
        command = ['cargo', 'test', '--locked', '--features', 'gui', '--lib']
        if args.target:
            command += ['--target', args.target]
        command += ['native_notification_dbus_fixture_delivers_counts_and_routes_click', '--', '--ignored', '--nocapture']
        env = dict(os.environ, P2P_NOTIFICATION_FIXTURE='1')
        subprocess.run(command, cwd=repo, env=env, check=True)
        payload = json.loads(output.read_text())
        assert payload['app'] == 'P2P File'
        assert payload['body'] == '已完成 3 项，失败或中断 1 项。点击查看任务。'
        assert 'default' in payload['actions'] and 'open' in payload['actions']
        assert payload['timeout'] == 5000
        print(json.dumps({'result': 'passed', 'proofs': ['native_dbus_counts_only_delivery', 'default_click_routes_internal_task_id']}, ensure_ascii=False))
    finally:
        process.terminate()
        process.wait(timeout=5)

if __name__ == '__main__':
    if sys.argv[1:2] == ['--host']:
        host(sys.argv[2])
    else:
        main()
