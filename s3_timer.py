# s3_timer.py
import time
import threading
from typing import Callable, Optional

class S3Timer:
    def __init__(
        self,
        send_tester_present_cb: Callable[[], None],
        expiry_callback: Callable[[], None],
        s3_timeout: float = 8.0,
        auto_tp: bool = True,
        tp_lead: float = 1.0,
    ):
        """
        send_tester_present_cb: function to send TesterPresent (3E 00)
        expiry_callback: function called when S3 expires
        s3_timeout: S3 duration in seconds
        auto_tp: automatically send TesterPresent before expiry
        tp_lead: seconds before expiry to auto-send TP
        """
        assert s3_timeout > 0
        assert tp_lead >= 0

        self.s3_timeout = s3_timeout
        self.auto_tp = auto_tp
        self.tp_lead = tp_lead
        self._send_tp = send_tester_present_cb
        self._expiry_cb = expiry_callback

        self._lock = threading.Lock()
        self._last_activity = 0.0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the S3 timer."""
        with self._lock:
            self._last_activity = time.time()
            if self._running:
                return
            self._running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stop the S3 timer."""
        with self._lock:
            self._running = False
            self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=0.5)

    def reset(self) -> None:
        """Reset last activity time."""
        with self._lock:
            self._last_activity = time.time()

    def send_tester_present(self) -> None:
        """Send TesterPresent manually and reset timer."""
        try:
            self._send_tp()
        finally:
            self.reset()

    def _run(self) -> None:
        """Internal loop monitoring S3."""
        check_interval = min(0.2, max(0.05, self.s3_timeout / 30.0))
        while not self._stop_event.is_set():
            with self._lock:
                if not self._running:
                    break
                now = time.time()
                elapsed = now - self._last_activity
                time_left = self.s3_timeout - elapsed

                pass_send = self.auto_tp and 0 < time_left <= self.tp_lead
                do_expire = elapsed >= self.s3_timeout

            if pass_send:
                try:
                    self._send_tp()
                except Exception as e:
                    print(f"[S3Timer] Warning: send_tester_present_cb raised: {e}")
                self.reset()

            if do_expire:
                with self._lock:
                    self._running = False
                    self._stop_event.set()
                try:
                    self._expiry_cb()
                except Exception as e:
                    print(f"[S3Timer] Warning: expiry_callback raised: {e}")
                return

            self._stop_event.wait(timeout=check_interval)
