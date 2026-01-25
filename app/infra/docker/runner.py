import asyncio
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass


@dataclass(frozen=True)
class DockerResult:
    returncode: int
    stdout: str
    stderr: str


class DockerCli:
    def __init__(self, analysis_id: str):
        self.analysis_id = str(analysis_id)

    @property
    def container_name(self) -> str:
        return f"analysis_{self.analysis_id}"

    @property
    def image_tag(self) -> str:
        return f"analysis_{self.analysis_id}"

    async def _run(self, command: list[str]) -> DockerResult:
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as pool:
            result = await loop.run_in_executor(
                pool,
                lambda: subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True),
            )
        return DockerResult(result.returncode, result.stdout or "", result.stderr or "")

    async def build(self, *, dockerfile_path: str, context_dir: str) -> DockerResult:
        return await self._run(
            [
                "powershell",
                "-command",
                f"docker build -t {self.image_tag} -f {dockerfile_path} {context_dir}\\",
            ],
        )

    async def run(self) -> DockerResult:
        return await self._run(
            [
                "powershell",
                "-command",
                f"docker run -it --isolation=process --name {self.container_name} {self.image_tag}",
            ],
        )

    async def diff(self) -> str:
        result = await self._run(
            [
                "powershell",
                "-command",
                f"docker diff {self.container_name}",
            ]
        )
        return (result.stdout or "").strip()

    async def logs(self) -> DockerResult:
        return await self._run(
            [
                "powershell",
                "-command",
                f"docker logs {self.container_name}",
            ]
        )

    async def stop_rm_rmi(self) -> None:
        await self._run(["powershell", "-command", f"docker stop {self.container_name}"])
        await self._run(["powershell", "-command", f"docker rm {self.container_name}"])
        await self._run(["powershell", "-command", f"docker rmi {self.image_tag}"])
