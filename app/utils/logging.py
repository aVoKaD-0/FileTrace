import requests
import json
from loguru import logger
from app.services.db_service import AnalysisDbService
from app.utils.websocket_manager import manager

class Logger:
    # Добавляем лог в файл только один раз при старте
    logger.add("app/logs/GlobalLog.log", level="INFO", rotation="10 GB")

    @staticmethod
    def log(message):
        logger.info(message)
        return None

    @staticmethod
    async def analysis_log(msg, analysis_id):
        try:
            db = await AnalysisDbService().get_database()
            try:
                result = await AnalysisDbService().get_result(analysis_id, db)
                if result:
                    result.docker_output += msg + "\n"
                    await db.commit()
            finally:
                await db.close()
            try:
                await manager.send_message(analysis_id, json.dumps({
                    "event": "docker_log",
                    "message": msg
                }))
            except Exception as ws_err:
                Logger.log(f"Ошибка отправки docker_log по WebSocket: {str(ws_err)}")
        except Exception as e:
            Logger.log(f"Ошибка в analysis_log: {str(e)}")
        return
    
    @staticmethod
    async def save_result(analysis_id, result_data):
        try:
            db = await AnalysisDbService().get_database()
            try:
                result = await AnalysisDbService().get_result(analysis_id, db)
                if result:
                    result.results = result_data
                    await db.commit()
            finally:
                await db.close()
        except Exception as e:
            Logger.log(f"Ошибка в save_result: {str(e)}")
        return 
    
    @staticmethod
    async def save_file_activity(analysis_id, history):
        try:
            db = await AnalysisDbService().get_database()
            try:
                result = await AnalysisDbService().get_result(analysis_id, db)
                analysis = await AnalysisDbService().get_analysis(analysis_id, db)
                if result:
                    analysis.status = "completed"
                    result.file_activity = history
                    await db.commit()
            finally:
                await db.close()
        except Exception as e:
            Logger.log(f"Ошибка в save_file_activity: {str(e)}")
        return

    @staticmethod
    async def update_history_on_error(analysis_id, error_message):
        try:
            db = await AnalysisDbService().get_database()
            try:
                result = await AnalysisDbService().get_result(analysis_id, db)
                analysis = await AnalysisDbService().get_analysis(analysis_id, db)
                if analysis and result:
                    analysis.status = "error"
                    result.docker_output = error_message
                    result.file_activity = ""
                    await db.commit()
            finally:
                await db.close()
        except Exception as e:
            Logger.log(f"Ошибка в update_history_on_error: {str(e)}")
        return None

    @staticmethod
    def send_result_to_server(analysis_id, result_data):
        url = "http://192.168.31.153:8080/submit-result/"
        
        payload = {
            "analysis_id": analysis_id,
            "result_data": result_data
        }
        headers = {"Content-Type": "application/json"}
        
        try:
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                Logger.log(f"[{analysis_id}] ✅ Результаты отправлены на сервер")
            else:
                Logger.log(f"[{analysis_id}] ❌ Ошибка при отправке: {response.status_code}")
        except Exception as e:
            Logger.log(f"[{analysis_id}] ⚠️ Ошибка соединения: {str(e)}")
        return None