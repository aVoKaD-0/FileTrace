import json
import os
from typing import Any, Optional

from app.infra.docker.paths import get_docker_root


class AnalysisArtifactsRepository:
    @staticmethod
    def get_base_dir(analysis_id: str) -> str:
        return os.path.join(get_docker_root(), "analysis", str(analysis_id))

    @classmethod
    def get_threat_report_path(cls, analysis_id: str) -> str:
        return os.path.join(cls.get_base_dir(analysis_id), "threat_report.json")

    @classmethod
    def get_clean_tree_csv_path(cls, analysis_id: str) -> str:
        return os.path.join(cls.get_base_dir(analysis_id), "clean_tree.csv")

    @classmethod
    def get_clean_tree_json_path(cls, analysis_id: str) -> str:
        return os.path.join(cls.get_base_dir(analysis_id), "clean_tree.json")

    @classmethod
    def get_trace_csv_path(cls, analysis_id: str) -> str:
        return os.path.join(cls.get_base_dir(analysis_id), "trace.csv")

    @classmethod
    def get_trace_etl_path(cls, analysis_id: str) -> str:
        return os.path.join(cls.get_base_dir(analysis_id), "trace.etl")

    @staticmethod
    def read_json(path: str) -> Any:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    @classmethod
    def read_json_if_exists(cls, path: str) -> Optional[Any]:
        if not os.path.exists(path):
            return None
        return cls.read_json(path)

    @classmethod
    def load_threat_report(cls, analysis_id: str) -> Optional[Any]:
        return cls.read_json_if_exists(cls.get_threat_report_path(analysis_id))
