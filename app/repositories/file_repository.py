import os
import json
from filelock import FileLock

class FileRepository:
    def save_file(file_path, data):
        with open(file_path, "w") as f:
            json.dump(data, f)

    def load_file(file_path):
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                return json.load(f)
        return {}
    
    def load_results(analysis_id: str):
        results_file = os.path.join("results", analysis_id, "results.json")
        lock = FileLock(results_file + ".lock")
        with lock:
            if os.path.exists(results_file):
                with open(results_file, "r", encoding="utf-8") as file:
                    return json.load(file)
            return {"file_activity": [], "docker_output": ""}

    def save_results(results, analysis_id: str):
        results_file = os.path.join("results", analysis_id, "results.json")
        lock = FileLock(results_file + ".lock")
        with lock:
            with open(results_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False)