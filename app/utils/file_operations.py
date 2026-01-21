import os
import uuid
import json
from datetime import datetime
from shutil import copyfileobj
from app.repositories.analysis import docker


project_dir = os.getcwd()


class FileOperations:
    @staticmethod
    def hash_based_storage(file_hash: str, pipeline_version: str):
        base = os.path.join(docker, "storage")

        structure = {
            "files": os.path.join(base, "files", file_hash),
            "analysis_raw": os.path.join(base, "analysis", file_hash, pipeline_version, "raw"),
            "analysis_processed": os.path.join(base, "analysis", file_hash, pipeline_version, "processed"),
            "analysis_results": os.path.join(base, "analysis", file_hash, pipeline_version, "results"),
        }

        for path in structure.values():
            os.makedirs(path, exist_ok=True)

        return structure

    @staticmethod
    def store_file_by_hash(file, file_hash: str, pipeline_version: str):
        storage = FileOperations.hash_based_storage(file_hash, pipeline_version)

        file_path = os.path.join(storage["files"], "original.exe")
        with open(file_path, "wb") as buffer:
            copyfileobj(file.file, buffer)

        metadata = {
            "filename": getattr(file, "filename", None),
            "size": os.path.getsize(file_path),
            "hash": file_hash,
            "pipeline_version": pipeline_version,
            "uploaded_at": datetime.utcnow().isoformat(),
        }

        with open(os.path.join(storage["files"], "metadata.json"), "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)

        return file_path, storage

    @staticmethod
    def user_upload(email):
        upload_path = os.path.join(docker, "analysis", email)
        os.makedirs(upload_path, exist_ok=True)
        return upload_path

    @staticmethod
    def user_file_upload(file, user_upload_folder):
        if not user_upload_folder:
            raise ValueError("Путь для загрузки файла не указан")

        file_path = os.path.join(user_upload_folder, file.filename)
        with open(file_path, "wb") as buffer:
            copyfileobj(file.file, buffer)

    def run_ID():
        return uuid.uuid4()