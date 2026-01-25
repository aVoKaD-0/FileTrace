import os
import json
import asyncio
from fastapi import HTTPException
from app.utils.logging import Logger
from app.services.analysis_status_service import AnalysisStatusService
from app.utils.websocket_manager import manager

from app.infra.docker import DockerCli, get_analysis_dir, write_analysis_dockerfile
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
        self.docker_cli = DockerCli(str(self.analysis_id))

    def update_dockerfile(self):
        write_analysis_dockerfile(analysis_id=str(self.analysis_id), filename=self.filename)

    async def build_docker(self):
        await AnalysisStatusService.analysis_log("Сборка Docker...", self.analysis_id)
        context_dir = get_analysis_dir(str(self.analysis_id))
        dockerfile_path = os.path.join(context_dir, "Dockerfile")
        result = await self.docker_cli.build(dockerfile_path=dockerfile_path, context_dir=context_dir)
        if result.returncode != 0:
            if result.stdout:
                await AnalysisStatusService.analysis_log(f"docker build stdout: {result.stdout.strip()}", self.analysis_id)
            if result.stderr:
                await AnalysisStatusService.analysis_log(f"docker build stderr: {result.stderr.strip()}", self.analysis_id)
            raise HTTPException(status_code=500, detail=f"docker build failed with code {result.returncode}")
        await AnalysisStatusService.analysis_log("Сборка Docker завершена", self.analysis_id)

    async def run_docker(self):
        await AnalysisStatusService.analysis_log("Запуск программы...", self.analysis_id)
        await asyncio.sleep(7)
        result = await self.docker_cli.run()
        if result.returncode != 0:
            if result.stdout:
                await AnalysisStatusService.analysis_log(f"docker run stdout: {result.stdout.strip()}", self.analysis_id)
            if result.stderr:
                await AnalysisStatusService.analysis_log(f"docker run stderr: {result.stderr.strip()}", self.analysis_id)
            raise HTTPException(status_code=500, detail=f"docker run failed with code {result.returncode}")
        await AnalysisStatusService.analysis_log("Программа завершила работу", self.analysis_id)
        return

    async def get_docker_output(self):
        await AnalysisStatusService.analysis_log("Получение логов...", self.analysis_id)
        result = await self.docker_cli.logs()
        if result.stdout:
            await AnalysisStatusService.analysis_log(f"docker logs stdout: {result.stdout.strip()}", self.analysis_id)
        if result.stderr:
            await AnalysisStatusService.analysis_log(f"docker logs stderr: {result.stderr.strip()}", self.analysis_id)

    async def get_file_changes(self):
        await AnalysisStatusService.analysis_log("Запуск отслеживания изменений...", self.analysis_id)
        changes = await self.docker_cli.diff()

        await AnalysisStatusService.analysis_log("Остановка программы...", self.analysis_id)

        await self.docker_cli.stop_rm_rmi()

        try:
            await AnalysisStatusService.analysis_log("Очистка логов...", self.analysis_id)
            loop = asyncio.get_event_loop()
            base_dir = get_analysis_dir(str(self.analysis_id))
            target_exe = self.filename
            result = await loop.run_in_executor(None, run_cleaner, target_exe, base_dir)
            await AnalysisStatusService.analysis_log("Очистка завершена", self.analysis_id)
        except Exception as e:
            await AnalysisStatusService.analysis_log(f"Ошибка при очистке логов: {str(e)}", self.analysis_id)
            raise HTTPException(status_code=500, detail=str(e))

        await AnalysisStatusService.save_file_activity(self.analysis_id, changes)
        return changes

    async def analyze(self):
        status_to_send = None
        etw_started = False
        docker_ran = False
        try:
            async with self.lock:
                await AnalysisStatusService.analysis_log("Анализ запущен", self.analysis_id)
 
            await AnalysisStatusService.update_analysis_status(self.analysis_id, "running")
            
            self.update_dockerfile()
            await self.build_docker()
            docker_built = True

            base_dir = get_analysis_dir(str(self.analysis_id))
            try:
                await AnalysisStatusService.analysis_log("Запуск отслеживания...", self.analysis_id)
                etw_collector.start_capture(
                    analysis_id=str(self.analysis_id),
                    output_dir=base_dir,
                    target_exe=self.filename,
                )
                etw_started = True
                await AnalysisStatusService.analysis_log("Отслеживание запущено", self.analysis_id)
            except Exception as etw_start_err:
                await AnalysisStatusService.analysis_log(f"ETW: ошибка старта захвата: {str(etw_start_err)}", self.analysis_id)
                raise
            
            run_docker_task = asyncio.create_task(self.run_docker())

            await asyncio.gather(run_docker_task)
            docker_ran = True

            try:
                await AnalysisStatusService.analysis_log("Остановка отслеживания...", self.analysis_id)
                etw_collector.stop_capture(str(self.analysis_id))
                await AnalysisStatusService.analysis_log("Отслеживание остановлено", self.analysis_id)
            except Exception as etw_stop_err:
                await AnalysisStatusService.analysis_log(f"ETW: ошибка остановки захвата: {str(etw_stop_err)}", self.analysis_id)
                raise

            try:
                trace_csv_path = os.path.join(base_dir, "trace.csv")
                if os.path.exists(trace_csv_path):
                    size_bytes = os.path.getsize(trace_csv_path)
                    with open(trace_csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                        line_count = sum(1 for _ in f)
                    await AnalysisStatusService.analysis_log(
                        f"trace.csv готов (строк={line_count})",
                        self.analysis_id,
                    )
                else:
                    await AnalysisStatusService.analysis_log("ETW: trace.csv не найден после stop_capture", self.analysis_id)
            except Exception as trace_stat_err:
                await AnalysisStatusService.analysis_log(f"ETW: не удалось прочитать trace.csv для диагностики: {str(trace_stat_err)}", self.analysis_id)

            if docker_ran:
                await self.get_file_changes()

            status_to_send = "completed"
            return "Анализ завершен"
        except Exception as e:
            Logger.log(f"Ошибка при анализе: {str(e)}")
            try:
                async with self.lock:
                    await AnalysisStatusService.update_history_on_error(self.analysis_id, "Анализ завершен с ошибкой")
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
                    await AnalysisStatusService.update_history_on_error(self.analysis_id, str(e))
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