import os

from app.infra.docker.paths import ensure_analysis_dir


def write_analysis_dockerfile(*, analysis_id: str, filename: str) -> str:
    base_dir = ensure_analysis_dir(analysis_id)
    dockerfile_path = os.path.join(base_dir, "Dockerfile")

    dockerfile_content = f"""FROM mcr.microsoft.com/windows/servercore:ltsc2022
WORKDIR C:/sandbox
COPY [\"{filename}\", \".\"]
RUN powershell -Command \"Set-ExecutionPolicy Bypass -Scope Process -Force\"
CMD [\"powershell\", \"-command\", \"Start-Process -FilePath 'C:/sandbox/{filename}' -NoNewWindow -PassThru; Start-Sleep -Seconds 180\"]
"""

    with open(dockerfile_path, "w", encoding="utf-8") as dockerfile:
        dockerfile.write(dockerfile_content)

    return dockerfile_path
