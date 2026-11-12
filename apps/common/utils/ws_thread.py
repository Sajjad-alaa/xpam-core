"""XPAM: sending to a WebSocket from a Redis subscription thread. A sync consumer sends through async_to_sync, which
looks for the server's event loop in the calling thread; a subscription thread has none, so each send ran on a new
loop of its own and failed ("attached to a different loop") as soon as it had to wait on the server's loop — the
socket was then closed. bind_server_loop() is called where the server's loop is known (a consumer method) and
returns the function the subscription thread calls before sending."""
import os

from asgiref.sync import SyncToAsync

__all__ = ['bind_server_loop']


def bind_server_loop():
    loop = getattr(SyncToAsync.threadlocal, 'main_event_loop', None)
    pid = os.getpid()

    def bind():
        if loop is not None and getattr(SyncToAsync.threadlocal, 'main_event_loop', None) is not loop:
            SyncToAsync.threadlocal.main_event_loop = loop
            SyncToAsync.threadlocal.main_event_loop_pid = pid

    return bind
