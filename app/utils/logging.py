import logging
import requests

class Logger:

    @staticmethod
    def log(message):
        logging.getLogger("app").info(str(message))
        return None

    @staticmethod
    def send_result_to_server(analysis_id, result_data):
        url = "http://192.168.31.153:8080/submit-result/"
        
        payload = {
            "analysis_id": analysis_id,
            "result_data": result_data,
        }
        headers = {"Content-Type": "application/json"}
        
        try:
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                Logger.log(f"[{analysis_id}] results sent")
            else:
                Logger.log(f"[{analysis_id}] send failed: {response.status_code}")
        except Exception as e:
            logging.getLogger("app").exception(f"[{analysis_id}] send failed")
            Logger.log(str(e))
        return None