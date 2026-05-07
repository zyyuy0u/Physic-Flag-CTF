from __future__ import annotations

import ctypes as ct
import logging
import os
import queue
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

try:
    from bcc import BPF
except ImportError as exc:
    raise ImportError(
        "Failed to import bcc. Install it with: "
        "apt install bpfcc-tools python3-bpfcc"
    ) from exc


log = logging.getLogger("defense.bpf_loader")


class Event(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_uint64),
        ("cgroup_id", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("family", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("saddr_v4", ct.c_uint32),
        ("daddr_v4", ct.c_uint32),
        ("saddr_v6", ct.c_ubyte * 16),
        ("daddr_v6", ct.c_ubyte * 16),
        ("comm", ct.c_char * 16),
    ]


@dataclass
class ParsedEvent:
    ts_ns: int
    recv_ts_ns: int
    pid: int
    comm: str
    family: int
    saddr: str
    daddr: str
    sport: int
    dport: int
    cgroup_id: int


class BpfReverseShellProbe:
    def __init__(
        self,
        web_container_name: str = "web-app",
        bpf_source_path: str | None = None,
        log: logging.Logger | None = None,
    ) -> None:
        self.web_container_name = web_container_name
        self.bpf_source_path = (
            Path(bpf_source_path)
            if bpf_source_path is not None
            else Path(__file__).with_name("bpf_probe.c")
        )
        self.log = log if log is not None else globals()["log"]

        self._bpf: BPF | None = None
        self._queue: queue.Queue[ParsedEvent] = queue.Queue()
        self._stopped = threading.Event()
        # Updated in start() and re-checked every REFRESH_INTERVAL_S by
        # _refresh_loop(). web-app restart yields a new cgroup id, so
        # without periodic reconciliation the kernel filter would
        # silently match nothing after the first restart.
        self._current_cgroup_id: int | None = None
        self._cgroup_lock = threading.Lock()
        self._refresh_thread: threading.Thread | None = None

    REFRESH_INTERVAL_S: float = 5.0

    def start(self, max_retries: int = 10, retry_interval_s: float = 1.0) -> None:
        """Resolve container cgroup id, load BPF, populate map.

        Retries cgroup resolution to tolerate web-app starting up slowly under
        ``depends_on`` — the container exists in Docker but its cgroup scope
        may take a beat to appear under /sys/fs/cgroup/system.slice/.
        """
        if self._bpf is not None:
            raise RuntimeError("BPF reverse-shell probe is already started")

        self._stopped.clear()
        container_id: str | None = None
        cgroup_path: str | None = None
        cgroup_id: int | None = None
        last_error: Exception | None = None
        for attempt in range(1, max_retries + 1):
            try:
                container_id = self._docker_container_id()
                cgroup_path, cgroup_id = self._resolve_cgroup(container_id)
                break
            except RuntimeError as exc:
                last_error = exc
                self.log.warning(
                    "Cgroup resolve attempt %d/%d failed: %s",
                    attempt, max_retries, exc,
                )
                time.sleep(retry_interval_s)
        if cgroup_id is None:
            raise RuntimeError(
                f"Could not resolve web-app cgroup after {max_retries} attempts"
            ) from last_error

        source = self.bpf_source_path.read_text(encoding="utf-8")

        bpf = BPF(text=source)
        bpf["cgroup_filter"][ct.c_uint64(cgroup_id)] = ct.c_uint8(1)
        bpf["events"].open_ring_buffer(self._on_event)

        self._bpf = bpf
        self._current_cgroup_id = cgroup_id

        self.log.info(
            "Started BPF reverse-shell probe: container=%s id=%s "
            "cgroup_path=%s cgroup_id=%d",
            self.web_container_name,
            container_id[:12],
            cgroup_path,
            cgroup_id,
        )

        # Reconcile the cgroup filter every REFRESH_INTERVAL_S so a
        # web-app restart (which changes its cgroup id) doesn't leave
        # the kernel filter stuck on a stale id. Polling is simpler
        # and miss-proof compared to subscribing to docker events,
        # and the 5s blind window is acceptable here — web-app is
        # not yet accepting connections during its own startup.
        self._refresh_thread = threading.Thread(
            target=self._refresh_loop,
            name="bpf-cgroup-refresh",
            daemon=True,
        )
        self._refresh_thread.start()

    def iter_events(self, poll_timeout_ms: int = 500) -> Iterator[ParsedEvent]:
        """Blocking generator yielding ParsedEvent dataclasses."""
        if self._bpf is None:
            raise RuntimeError("BPF reverse-shell probe is not started")
        if poll_timeout_ms < 0:
            raise ValueError("poll_timeout_ms must be non-negative")

        while not self._stopped.is_set():
            self._bpf.ring_buffer_poll(poll_timeout_ms)
            while not self._stopped.is_set():
                try:
                    yield self._queue.get_nowait()
                except queue.Empty:
                    break

    def stop(self) -> None:
        self._stopped.set()
        t = self._refresh_thread
        if t is not None and t.is_alive():
            # Cover the worst case: thread is mid-`docker inspect`
            # (10 s timeout) when stop is called. Adding 2 s of slack
            # so join doesn't return while the thread is still in the
            # subprocess wait.
            t.join(timeout=12.0)

    def _refresh_loop(self) -> None:
        """Poll web-app's cgroup id every REFRESH_INTERVAL_S.

        Uses Event.wait() so stop() can interrupt the sleep
        immediately rather than waiting for the next tick. Each tick
        calls _refresh_cgroup() which is cheap on no-change (compares
        old vs new id and returns early). If web-app is mid-restart
        and docker inspect / cgroup resolution fails, the helper logs
        a warning and the loop retries on the next tick.

        The bare-except guard is deliberate: if any unexpected error
        escapes _refresh_cgroup(), losing the refresh thread would
        silently degrade the probe to "stuck on the original cgroup
        id, blind to all subsequent web-app restarts". Logging and
        retrying is strictly safer.
        """
        while not self._stopped.wait(self.REFRESH_INTERVAL_S):
            try:
                self._refresh_cgroup()
            except Exception as exc:
                self.log.warning("cgroup refresh tick failed: %s", exc)

    def _refresh_cgroup(self) -> None:
        """Re-resolve web-app cgroup and update the BPF filter map atomically."""
        try:
            container_id = self._docker_container_id()
            cgroup_path, new_id = self._resolve_cgroup(container_id)
        except RuntimeError as exc:
            self.log.warning("cgroup refresh failed: %s", exc)
            return

        with self._cgroup_lock:
            old_id = self._current_cgroup_id
            if old_id == new_id:
                return  # same container instance — no-op
            assert self._bpf is not None
            try:
                self._bpf["cgroup_filter"][ct.c_uint64(new_id)] = ct.c_uint8(1)
                if old_id is not None:
                    try:
                        del self._bpf["cgroup_filter"][ct.c_uint64(old_id)]
                    except KeyError:
                        pass
                self._current_cgroup_id = new_id
            except Exception as exc:
                self.log.error("Failed to update BPF cgroup_filter map: %s", exc)
                return

        self.log.info(
            "Refreshed cgroup_id: %s -> %d (path=%s) for container=%s",
            old_id, new_id, cgroup_path, self.web_container_name,
        )

    def _docker_container_id(self) -> str:
        try:
            result = subprocess.run(
                [
                    "docker",
                    "inspect",
                    self.web_container_name,
                    "--format",
                    "{{.Id}}",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("docker command not found while resolving cgroup id") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "").strip()
            if detail:
                detail = f": {detail}"
            raise RuntimeError(
                f"failed to inspect Docker container {self.web_container_name!r}{detail}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"timed out inspecting Docker container {self.web_container_name!r}"
            ) from exc

        container_id = result.stdout.strip()
        if not container_id:
            raise RuntimeError(
                f"docker inspect returned an empty id for {self.web_container_name!r}"
            )
        return container_id

    def _resolve_cgroup(self, container_id: str) -> tuple[str, int]:
        paths = [
            f"/sys/fs/cgroup/system.slice/docker-{container_id}.scope",
            f"/sys/fs/cgroup/docker/{container_id}",
        ]

        # Stat each path directly instead of exists()-then-stat() to
        # avoid a TOCTOU race: during a web-app restart the cgroup
        # directory can disappear between the two calls and a
        # FileNotFoundError escaping here would kill the refresh
        # thread silently.
        for path in paths:
            try:
                return path, os.stat(path).st_ino
            except FileNotFoundError:
                continue

        raise RuntimeError(
            "could not resolve Docker cgroup path for container "
            f"{self.web_container_name!r} ({container_id[:12]}). Tried: "
            + ", ".join(paths)
        )

    def _on_event(self, _ctx: int, data: int, size: int) -> None:
        if size < ct.sizeof(Event):
            self.log.warning(
                "Ignoring short BPF event: size=%d expected=%d",
                size,
                ct.sizeof(Event),
            )
            return

        raw = ct.string_at(data, ct.sizeof(Event))
        event = Event.from_buffer_copy(raw)
        parsed = self._parse_event(event)
        self._queue.put(parsed)

    def _parse_event(self, event: Event) -> ParsedEvent:
        if event.family == socket.AF_INET:
            saddr = self._inet4_from_event(event, "saddr_v4")
            daddr = self._inet4_from_event(event, "daddr_v4")
        elif event.family == socket.AF_INET6:
            saddr = socket.inet_ntop(socket.AF_INET6, bytes(event.saddr_v6))
            daddr = socket.inet_ntop(socket.AF_INET6, bytes(event.daddr_v6))
        else:
            saddr = ""
            daddr = ""
            self.log.warning("Ignoring unknown address family in event: %d", event.family)

        return ParsedEvent(
            ts_ns=int(event.ts_ns),
            recv_ts_ns=time.monotonic_ns(),
            pid=int(event.pid),
            comm=self._decode_comm(event.comm),
            family=int(event.family),
            saddr=saddr,
            daddr=daddr,
            sport=int(event.sport),
            dport=int(event.dport),
            cgroup_id=int(event.cgroup_id),
        )

    @staticmethod
    def _inet4_from_event(event: Event, field_name: str) -> str:
        offset = getattr(Event, field_name).offset
        packed = ct.string_at(ct.addressof(event) + offset, 4)
        return socket.inet_ntop(socket.AF_INET, packed)

    @staticmethod
    def _decode_comm(comm: bytes) -> str:
        return bytes(comm).split(b"\x00", 1)[0].decode("utf-8", errors="replace")
