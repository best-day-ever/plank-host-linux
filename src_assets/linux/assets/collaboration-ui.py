#!/usr/bin/python3
"""Desktop-owner consent and participant controls for Fernweh collaboration.

The root worker authenticates this process with SO_PEERCRED. This fixed helper
has no network listener, bearer token, grant, or root privileges. Closing it
revokes all participants. Sensitive buttons appear only after the worker has
acknowledged suspension of all collaborator input.
"""
import json
import os
import socket
import struct
import time

import gi
gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk


class Consent:
    """Keep an owner-visible indicator and a host-acknowledged permission panel."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.sock.connect("/run/plank/collaboration.sock")
        credentials = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        if struct.unpack("3i", credentials)[1] != 0 or os.getuid() == 0:
            raise PermissionError("The consent channel is not the root worker")
        self.sock.setblocking(False)
        self.last_message = time.monotonic()
        self.signature = None
        self.panel_requested = False
        self.panel_acknowledged = False
        self.indicator = Gtk.Window(title="Fernweh collaboration")
        self.indicator.set_keep_above(True)
        self.indicator.set_resizable(False)
        self.indicator.connect("delete-event", self.quit)
        self.indicator_button = Gtk.Button(label="Fernweh collaboration — Manage")
        self.indicator_button.connect("clicked", self.open_panel)
        self.indicator.add(self.indicator_button)
        self.panel = Gtk.Window(title="Fernweh collaboration permissions")
        self.panel.set_keep_above(True)
        self.panel.set_default_size(470, 160)
        self.panel.connect("delete-event", self.close_panel)
        self.rows = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.rows.set_border_width(16)
        self.panel.add(self.rows)
        GLib.io_add_watch(self.sock.fileno(), GLib.IO_IN | GLib.IO_HUP | GLib.IO_ERR, self.receive)
        GLib.timeout_add(500, self.heartbeat)
        self.send({"panel_open": False})

    def send(self, body):
        """Send a small owner action; errors end sharing immediately."""
        try:
            self.sock.send(json.dumps(body).encode("utf-8"))
        except OSError:
            self.quit()

    def open_panel(self, *_):
        """Ask the host to suspend guests before exposing permission buttons."""
        self.panel_requested = True
        self.send({"panel_open": True})

    def close_panel(self, *_):
        """Hide sensitive controls before allowing guest input again."""
        self.panel.hide()
        self.panel_requested = False
        self.panel_acknowledged = False
        self.send({"panel_open": False})
        return True

    def decide(self, _button, request_id, permission):
        """Authorize only a panel whose suspension was acknowledged by the host."""
        if self.panel_acknowledged:
            self.send({"request_id": request_id, "permission": permission})

    def receive(self, _fd, condition):
        """Replace participant controls from one bounded worker snapshot."""
        if condition & (GLib.IO_HUP | GLib.IO_ERR):
            self.quit()
            return False
        try:
            packet = self.sock.recv(65537)
            if not packet or len(packet) > 65536:
                raise ValueError("Invalid consent snapshot")
            body = json.loads(packet)
        except (OSError, ValueError):
            self.quit()
            return False
        self.last_message = time.monotonic()
        requests = body.get("requests", [])
        pending = any(item.get("state") == "pending" for item in requests)
        if pending and not self.panel_requested:
            self.open_panel()
        self.panel_acknowledged = body.get("panel_open") is True and self.panel_requested
        signature = json.dumps(requests, sort_keys=True)
        if signature != self.signature:
            self.signature = signature
            for child in self.rows.get_children():
                self.rows.remove(child)
            title = Gtk.Label(label="Only you can approve access. Close this app to end sharing.")
            title.set_line_wrap(True)
            self.rows.pack_start(title, False, False, 0)
            for item in requests:
                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
                state = item.get("state", "pending")
                name = item.get("guest_name", "Another user")
                label = Gtk.Label(label=f"{name} — " + {
                    "pending": "requests to join your desktop", "view": "view only", "control": "can interact"
                }.get(state, state))
                label.set_xalign(0)
                box.pack_start(label, False, False, 0)
                buttons = Gtk.Box(spacing=8)
                actions = [("Decline", "deny"), ("Allow view only", "view"), ("Allow interaction", "control")] if state == "pending" else [
                    ("View only", "view"), ("Allow interaction", "control"), ("Disconnect", "revoke")]
                for text, permission in actions:
                    button = Gtk.Button(label=text)
                    button.connect("clicked", self.decide, item["request_id"], permission)
                    buttons.pack_start(button, False, False, 0)
                box.pack_start(buttons, False, False, 0)
                self.rows.pack_start(box, False, False, 0)
            close = Gtk.Button(label="Done")
            close.connect("clicked", self.close_panel)
            self.rows.pack_start(close, False, False, 0)
            self.indicator_button.set_label(f"Fernweh: {len(requests)} participant request(s) — Manage")
        self.rows.set_sensitive(self.panel_acknowledged)
        if requests:
            self.indicator.show_all()
        else:
            self.indicator.hide()
            self.close_panel()
        if self.panel_acknowledged:
            self.panel.show_all()
            if pending:
                self.panel.present()
        return True

    def heartbeat(self):
        """A stalled or missing helper cannot leave a hidden collaboration grant."""
        if time.monotonic() - self.last_message > 3:
            self.quit()
            return False
        self.send({"panel_open": self.panel_requested})
        return True

    def quit(self, *_):
        """Socket closure causes immediate host-side revocation."""
        self.sock.close()
        Gtk.main_quit()
        return False


if __name__ == "__main__":
    consent = Consent()
    Gtk.main()
