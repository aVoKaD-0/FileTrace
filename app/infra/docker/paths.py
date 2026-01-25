import os


def get_docker_root() -> str:
    return os.path.join(os.getcwd(), "dockerer")


def get_analysis_dir(analysis_id: str) -> str:
    return os.path.join(get_docker_root(), "analysis", str(analysis_id))


def ensure_analysis_dir(analysis_id: str) -> str:
    path = get_analysis_dir(analysis_id)
    os.makedirs(path, exist_ok=True)
    return path
