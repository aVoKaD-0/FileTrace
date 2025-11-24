import os
import uuid
from shutil import copyfileobj
from app.repositories.analysis import docker


project_dir = os.getcwd()


class FileOperations:
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