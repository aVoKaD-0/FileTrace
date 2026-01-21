import os
import subprocess
import time
from typing import Optional

import requests

import logging


logger = logging.getLogger(__name__)


class EtwCollectorService:
    def __init__(self, base_url: str = "http://127.0.0.1:8765"):
        self.base_url = base_url.rstrip("/")
        self.process: Optional[subprocess.Popen] = None

    def start_process(self) -> None:
        if self.process and self.process.poll() is None:
            return

        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        project_dir = os.path.join(repo_root, "etw_collector")

        cmd = [
            "dotnet",
            "run",
            "--project",
            os.path.join(project_dir, "EtwCollector.csproj"),
            "--configuration",
            "Release",
        ]

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )

        self.wait_ready(timeout_s=20)

    def wait_ready(self, timeout_s: int = 20) -> None:
        start = time.time()
        last_err: Optional[Exception] = None
        while time.time() - start < timeout_s:
            try:
                r = requests.get(f"{self.base_url}/health", timeout=1)
                if r.ok:
                    return
            except Exception as e:
                last_err = e
            time.sleep(0.5)

        extra = ""
        try:
            if self.process and self.process.poll() is not None and self.process.stderr:
                err = self.process.stderr.read()
                if err:
                    extra = f" Process stderr: {err.strip()}"
        except Exception:
            pass

        raise RuntimeError(f"EtwCollector did not become ready in {timeout_s}s. Last error: {last_err}.{extra}")

    def stop_process(self) -> None:
        if not self.process:
            return

        if self.process.poll() is not None:
            return

        try:
            self.process.terminate()
        except Exception:
            pass

    def ensure_running(self) -> None:
        try:
            self.wait_ready(timeout_s=1)
            return
        except Exception:
            pass

        logger.info("Starting EtwCollector process...")
        self.start_process()

    def start_capture(self, analysis_id: str, output_dir: str, target_exe: str) -> None:
        self.ensure_running()
        payload = {
            "analysisId": analysis_id,
            "outputDir": output_dir,
            "targetExe": target_exe,
        }
        r = requests.post(f"{self.base_url}/start", json=payload, timeout=5)
        if not r.ok:
            raise RuntimeError(f"EtwCollector /start failed: {r.status_code} {r.text}")

    def stop_capture(self, analysis_id: str) -> None:
        self.ensure_running()
        payload = {"analysisId": analysis_id}
        r = requests.post(f"{self.base_url}/stop", json=payload, timeout=10)
        if not r.ok:
            raise RuntimeError(f"EtwCollector /stop failed: {r.status_code} {r.text}")
