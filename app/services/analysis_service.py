import os
import json
import time
import asyncio
import subprocess
from fastapi import HTTPException
from app.utils.logging import Logger
from app.utils.websocket_manager import manager
from concurrent.futures import ThreadPoolExecutor
from app.repositories.analysis import docker
from app.utils.cleaner import run_cleaner
from app.services.etw_collector_singleton import etw_collector

class AnalysisService:
    def __init__(self, filename: str, analysis_id: str, uuid: str, file_hash: str, pipeline_version: str):
        self.db = None
        self.uuid = uuid
        self.filename = filename
        self.analysis_id = analysis_id 
        self.file_hash = file_hash
        self.pipeline_version = pipeline_version
        self.lock = asyncio.Lock() 

    def update_dockerfile(self):
        file = self.filename[:-4]
        dockerfile_content = f"""FROM mcr.microsoft.com/windows/servercore:ltsc2022
WORKDIR C:\\sandbox
COPY ["{self.filename}", "."]
RUN powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force"
CMD ["powershell", "-command", "Start-Process -FilePath 'C:\\sandbox\\{self.filename}' -NoNewWindow -PassThru; Start-Sleep -Seconds 180"]
"""
        
        if not os.path.exists(f"{docker}\\analysis\\{self.analysis_id}"):
            os.makedirs(f"{docker}\\analysis\\{self.analysis_id}")
        
        with open(f"{docker}\\analysis\\{self.analysis_id}\\Dockerfile", 'w') as dockerfile:
            dockerfile.write(dockerfile_content)

    async def build_docker(self):
        await Logger.analysis_log("Сборка Docker...", self.analysis_id)
        await self._run_checked(
            ["powershell", "-command", f"docker build -t analysis_{self.analysis_id} -f {docker}\\analysis\\{self.analysis_id}\\Dockerfile {docker}\\analysis\\{self.analysis_id}\\"],
            "docker build",
        )
        await Logger.analysis_log("Сборка Docker завершена", self.analysis_id)

    async def run_in_executor(self, command):
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as pool:
            result = await loop.run_in_executor(
                pool, 
                lambda: subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            )
        return result

    async def _run_checked(self, command, step_name: str):
        result = await self.run_in_executor(command)
        if result.returncode != 0:
            if result.stdout:
                await Logger.analysis_log(f"{step_name} stdout: {result.stdout.strip()}", self.analysis_id)
            if result.stderr:
                await Logger.analysis_log(f"{step_name} stderr: {result.stderr.strip()}", self.analysis_id)
            raise HTTPException(status_code=500, detail=f"{step_name} failed with code {result.returncode}")
        return result

    async def run_docker(self):
        await Logger.analysis_log("Запуск программы...", self.analysis_id)
        await asyncio.sleep(7)
        command = ["powershell", "-command", f"docker run -it --isolation=process --name analysis_{self.analysis_id} analysis_{self.analysis_id}"]
        await self._run_checked(command, "docker run")
        await Logger.analysis_log("Программа завершила работу", self.analysis_id)
        return

    async def get_docker_output(self):
        await Logger.analysis_log("Получение логов...", self.analysis_id)
        process = await asyncio.create_subprocess_exec(
            "powershell", "-command", f"docker logs analysis_{self.analysis_id}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

    async def get_file_changes(self):
        await Logger.analysis_log("Запуск отслеживания изменений...", self.analysis_id)
        command = ["powershell", "-command", f"docker diff analysis_{self.analysis_id}"]
        result = await self.run_in_executor(command)
        changes = result.stdout.strip()
        if result.stderr:
            await Logger.analysis_log(f"docker diff stderr: {result.stderr.strip()}", self.analysis_id)

        await Logger.analysis_log("Остановка программы...", self.analysis_id)

        await self.run_in_executor(["powershell", "-command", f"docker stop analysis_{self.analysis_id}"])
        await self.run_in_executor(["powershell", "-command", f"docker rm analysis_{self.analysis_id}"])
        await self.run_in_executor(["powershell", "-command", f"docker rmi analysis_{self.analysis_id}"])

        try:
            await Logger.analysis_log("Очистка логов...", self.analysis_id)
            loop = asyncio.get_event_loop()
            base_dir = f"{docker}\\analysis\\{self.analysis_id}"
            target_exe = self.filename
            result = await loop.run_in_executor(None, run_cleaner, target_exe, base_dir)
            await Logger.analysis_log("Очистка завершена", self.analysis_id)
        except Exception as e:
            await Logger.analysis_log(f"Ошибка при очистке логов: {str(e)}", self.analysis_id)
            raise HTTPException(status_code=500, detail=str(e))

        await Logger.save_file_activity(self.analysis_id, changes)
        return changes

    async def analyze(self):
        status_to_send = None
        etw_started = False
        docker_built = False
        docker_ran = False
        try:
            async with self.lock:
                await Logger.analysis_log("Анализ запущен", self.analysis_id)
 
            await Logger.update_analysis_status(self.analysis_id, "running")
            
            self.update_dockerfile()
            await self.build_docker()
            docker_built = True

            base_dir = f"{docker}\\analysis\\{self.analysis_id}"
            try:
                await Logger.analysis_log("Запуск отслеживания...", self.analysis_id)
                etw_collector.start_capture(
                    analysis_id=str(self.analysis_id),
                    output_dir=base_dir,
                    target_exe=self.filename,
                )
                etw_started = True
                await Logger.analysis_log("Отслеживание запущено", self.analysis_id)
            except Exception as etw_start_err:
                await Logger.analysis_log(f"ETW: ошибка старта захвата: {str(etw_start_err)}", self.analysis_id)
                raise
            
            run_docker_task = asyncio.create_task(self.run_docker())

            await asyncio.gather(run_docker_task)
            docker_ran = True

            try:
                await Logger.analysis_log("Остановка отслеживания...", self.analysis_id)
                etw_collector.stop_capture(str(self.analysis_id))
                await Logger.analysis_log("Отслеживание остановлено", self.analysis_id)
            except Exception as etw_stop_err:
                await Logger.analysis_log(f"ETW: ошибка остановки захвата: {str(etw_stop_err)}", self.analysis_id)
                raise

            try:
                trace_csv_path = os.path.join(base_dir, "trace.csv")
                if os.path.exists(trace_csv_path):
                    size_bytes = os.path.getsize(trace_csv_path)
                    with open(trace_csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                        line_count = sum(1 for _ in f)
                    await Logger.analysis_log(
                        f"trace.csv готов (строк={line_count})",
                        self.analysis_id,
                    )
                else:
                    await Logger.analysis_log("ETW: trace.csv не найден после stop_capture", self.analysis_id)
            except Exception as trace_stat_err:
                await Logger.analysis_log(f"ETW: не удалось прочитать trace.csv для диагностики: {str(trace_stat_err)}", self.analysis_id)

            if docker_ran:
                await self.get_file_changes()

            status_to_send = "completed"
            return "Анализ завершен"
        except Exception as e:
            Logger.log(f"Ошибка при анализе: {str(e)}")
            try:
                async with self.lock:
                    await Logger.update_history_on_error(self.analysis_id, "Анализ завершен с ошибкой")
                if etw_started:
                    try:
                        etw_collector.stop_capture(str(self.analysis_id))
                    except Exception:
                        pass

                result = None
                if docker_ran:
                    result = await self.get_file_changes()
                status_to_send = "error"
                return result or f"Ошибка анализа: {str(e)}"
            except Exception as inner_e:
                Logger.log(f"Внутренняя ошибка при обработке исключения: {str(inner_e)}")
                async with self.lock:
                    await Logger.update_history_on_error(self.analysis_id, str(e))
                status_to_send = "error"
                return f"Ошибка анализа: {str(e)}"
        finally:
            if status_to_send:
                try:
                    await manager.send_message(self.analysis_id, json.dumps({
                        "status": status_to_send
                    }))
                except Exception as ws_err:
                    Logger.log(f"Ошибка отправки статуса анализа по WebSocket: {str(ws_err)}")