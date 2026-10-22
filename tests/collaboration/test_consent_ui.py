#!/usr/bin/python3
"""Exercise actual GTK consent controls under Xvfb, with an isolated fake owner channel."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest import mock

try:
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import GLib, Gtk
    GTK_AVAILABLE = Gtk.init_check()[0]
except ImportError:
    GTK_AVAILABLE = False


class OwnerChannel:
    """An isolated trusted-worker channel; never connects to a workstation."""

    def __init__(self):
        self.sent = []
        self.packet = b""
        self.closed = False

    def connect(self, _path):
        pass

    def getsockopt(self, *_args):
        return struct.pack("3i", 1234, 0, 0)

    def setblocking(self, _value):
        pass

    def fileno(self):
        return 42

    def send(self, packet):
        self.sent.append(json.loads(packet))
        return len(packet)

    def recv(self, _maximum):
        return self.packet

    def close(self):
        self.closed = True


@unittest.skipUnless(GTK_AVAILABLE, "requires GTK3 and an X11 display (run with xvfb-run)")
class ConsentControls(unittest.TestCase):
    """Owner controls are unusable until the worker suspends guest interaction."""

    def setUp(self):
        source = Path(__file__).resolve().parents[2] / "src_assets/linux/assets/collaboration-ui.py"
        spec = importlib.util.spec_from_file_location("collaboration_ui", source)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.channel = OwnerChannel()
        self.patches = [
            mock.patch.object(self.module.socket, "socket", return_value=self.channel),
            mock.patch.object(self.module.os, "getuid", return_value=1001),
            mock.patch.object(GLib, "io_add_watch", return_value=1),
            mock.patch.object(GLib, "timeout_add", return_value=1),
            mock.patch.object(Gtk, "main_quit"),
        ]
        for patch in self.patches:
            patch.start()
        self.ui = self.module.Consent()

    def tearDown(self):
        self.ui.indicator.destroy()
        self.ui.panel.destroy()
        for patch in reversed(self.patches):
            patch.stop()

    def snapshot(self, state="pending", panel_open=False):
        self.channel.packet = json.dumps({"panel_open": panel_open, "requests": [{
            "request_id": "a" * 64, "guest_name": "support", "state": state, "connected": False,
        }]}).encode()
        self.ui.receive(42, GLib.IO_IN)

    def test_pending_consent_waits_for_host_suspension_before_showing_controls(self):
        self.snapshot()
        self.assertEqual(self.channel.sent[-1], {"panel_open": True})
        self.assertFalse(self.ui.panel.get_visible())
        self.assertFalse(self.ui.rows.get_sensitive())
        self.snapshot(panel_open=True)
        self.assertTrue(self.ui.panel.get_visible())
        self.assertTrue(self.ui.rows.get_sensitive())
        self.ui.decide(None, "a" * 64, "view")
        self.assertEqual(self.channel.sent[-1]["permission"], "view")

    def test_stale_or_unacknowledged_panel_cannot_approve(self):
        self.snapshot()
        before = len(self.channel.sent)
        self.ui.decide(None, "a" * 64, "control")
        self.assertEqual(len(self.channel.sent), before)

    def test_done_hides_controls_before_reenabling_guest_input(self):
        self.snapshot()
        self.snapshot(state="control", panel_open=True)
        self.ui.close_panel()
        self.assertFalse(self.ui.panel.get_visible())
        self.assertFalse(self.ui.panel_acknowledged)
        self.assertEqual(self.channel.sent[-1], {"panel_open": False})

    def test_indicator_close_and_lost_worker_close_authority_channel(self):
        self.ui.quit()
        self.assertTrue(self.channel.closed)
        self.assertFalse(self.ui.receive(42, GLib.IO_HUP))


if __name__ == "__main__":
    unittest.main()
