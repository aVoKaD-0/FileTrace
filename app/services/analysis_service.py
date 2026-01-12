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

class AnalysisService:
    def __init__(self, filename: str, analysis_id: str, uuid: str):
        self.db = None
        self.uuid = uuid
        self.filename = filename
        self.analysis_id = analysis_id 
        self.lock = asyncio.Lock() 


    def update_dockerfile(self):
        file = self.filename[:-4]
        dockerfile_content = f"""FROM mcr.microsoft.com/windows/servercore:ltsc2022
WORKDIR C:\\\\sandbox
COPY {self.filename} .
RUN powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force"
CMD ["powershell", "-command", "Start-Process -FilePath 'C:\\\\sandbox\\\\{self.filename}' -NoNewWindow -PassThru; Start-Sleep -Seconds 180"]
"""
        
        if not os.path.exists(f"{docker}\\analysis\\{self.analysis_id}"):
            os.makedirs(f"{docker}\\analysis\\{self.analysis_id}")
        
        with open(f"{docker}\\analysis\\{self.analysis_id}\\Dockerfile", 'w') as dockerfile:
            dockerfile.write(dockerfile_content)

    async def build_docker(self):
        await Logger.analysis_log("Сборка Docker-образа...", self.analysis_id)
        await self.run_in_executor(["powershell", "-command", f"docker build -t analysis_{self.analysis_id} -f {docker}\\analysis\\{self.analysis_id}\\Dockerfile {docker}\\analysis\\{self.analysis_id}\\"])

    async def run_in_executor(self, command):
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as pool:
            result = await loop.run_in_executor(
                pool, 
                lambda: subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            )
        return result

    async def run_docker(self):
        await Logger.analysis_log("Запуск контейнера...", self.analysis_id)
        await asyncio.sleep(7)
        command = ["powershell", "-command", f"docker run -it --isolation=process --name analysis_{self.analysis_id} analysis_{self.analysis_id}"]
        result = await self.run_in_executor(command)
        await Logger.analysis_log("Контейнер успешно завершил работу.", self.analysis_id)
        await self.stop_etw() 
        await self.get_file_changes()
        return

    async def get_docker_output(self):
        await Logger.analysis_log("Получение логов...", self.analysis_id)
        process = await asyncio.create_subprocess_exec(
            "powershell", "-command", f"docker logs analysis_{self.analysis_id}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

    async def run_etw(self):
        await Logger.analysis_log("Запуск ETW для мониторинга файлов...", self.analysis_id)
        etw_command = ["powershell", "-command", f"xperf -on PROC_THREAD+LOADER+FILE_IO -f {docker}\\analysis\\{self.analysis_id}\\trace.etl"]
        result = await self.run_in_executor(etw_command)
        await Logger.analysis_log("ETW успешно запущен.", self.analysis_id)

    async def stop_etw(self):
        try:
            await Logger.analysis_log("Остановка ETW...", self.analysis_id)
            command = ["powershell", "-command", "xperf -stop"]
            result = await self.run_in_executor(command)
            await Logger.analysis_log("ETW успешно остановлен.", self.analysis_id)    
            await self.export_etl()
        except Exception as e:
            await Logger.analysis_log(f"Ошибка при остановке ETW: {str(e)}", self.analysis_id)

    async def export_result(self):
        await Logger.analysis_log("Экспорт логов ETW...", self.analysis_id)
        process = await asyncio.create_subprocess_exec(
            "powershell", "-command", f"xperf -i {docker}\\{self.analysis_id}\\trace.etl -o {docker}\\analysis\\{self.analysis_id}\\trace.txt",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await Logger.analysis_log("Логи ETW успешно экспортированы.", self.analysis_id)

    async def export_etl(self):
        etl = f"{docker}\\analysis\\{self.analysis_id}\\trace.etl"
        output_csv = f"{docker}\\analysis\\{self.analysis_id}\\trace.csv"
        output_json = f"{docker}\\analysis\\{self.analysis_id}\\trace.json"
        
        await Logger.analysis_log("Экспорт ETL в CSV...", self.analysis_id)
        
        tracerpt_command = ["powershell", "-command", f"tracerpt {etl} -o {output_csv} -of CSV"]
        await self.run_in_executor(tracerpt_command)
        
        await Logger.analysis_log("Экспорт ETL в JSON...", self.analysis_id)
        
        json_command = ["powershell", "-command", f"Import-Csv {output_csv} | ConvertTo-Json | Out-File {output_json}"]
        await self.run_in_executor(json_command)
        
        await Logger.analysis_log("ETL успешно экспортирован.", self.analysis_id)
        
        await manager.send_message(self.analysis_id, json.dumps({
            "event": "etl_converted", 
            "message": "ETL данные успешно конвертированы"
        }))

    async def get_file_changes(self):
        await Logger.analysis_log(f"📄 Отслеживание изменений файлов в контейнере Docker.", self.analysis_id)
        command = ["powershell", "-command", f"docker diff analysis_{self.analysis_id}"]
        result = await self.run_in_executor(command)
        changes = result.stdout.strip()

        await self.run_in_executor(["powershell", "-command", f"docker stop analysis_{self.analysis_id}"])
        await self.run_in_executor(["powershell", "-command", f"docker rm analysis_{self.analysis_id}"])
        await self.run_in_executor(["powershell", "-command", f"docker rmi analysis_{self.analysis_id}"])

        try:
            await Logger.analysis_log("Запуск очистки логов файловой активности...", self.analysis_id)
            loop = asyncio.get_event_loop()
            base_dir = f"{docker}\\analysis\\{self.analysis_id}"
            target_exe = self.filename
            result = await loop.run_in_executor(None, run_cleaner, target_exe, base_dir)
            await Logger.analysis_log("Очистка логов завершена. Созданы clean_tree.csv, clean_tree.json, threat_report.json.", self.analysis_id)
        except Exception as e:
            await Logger.analysis_log(f"Ошибка при очистке логов: {str(e)}", self.analysis_id)
            raise HTTPException(status_code=500, detail=str(e))

        await Logger.save_file_activity(self.analysis_id, changes)
        return changes

    async def analyze(self):
        status_to_send = None
        try:
            async with self.lock:
                await Logger.analysis_log("Анализ запущен", self.analysis_id)
            
            self.update_dockerfile()
            await self.build_docker()
            
            run_etw_task = asyncio.create_task(self.run_etw())
            run_docker_task = asyncio.create_task(self.run_docker())
            
            await asyncio.gather(run_docker_task, run_etw_task)

            status_to_send = "completed"
            return "Анализ завершен"
        except Exception as e:
            Logger.log(f"Ошибка при анализе: {str(e)}")
            try:
                async with self.lock:
                    await Logger.update_history_on_error(self.analysis_id, "Анализ завершен с ошибкой")
                await self.stop_etw()
                result = await self.get_file_changes()
                status_to_send = "error"
                return result
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