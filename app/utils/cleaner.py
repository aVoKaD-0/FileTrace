import csv
import json
import re
import sys
import os

# === НАСТРОЙКИ ===
TARGET_EXE = "mc1.exe"        
CSV_INPUT = "trace.csv"       
JSON_INPUT = "trace.json"     
CSV_OUTPUT = "clean_tree.csv" 
JSON_OUTPUT = "clean_tree.json" 
REPORT_OUTPUT = "threat_report.json" 

def hex_to_int(val):
    try:
        clean_val = str(val).strip().replace('"', '').replace("'", "")
        if '0x' in clean_val.lower():
            return int(clean_val, 16)
        return int(clean_val)
    except:
        return 0

def get_pids_from_row(row):
    text = str(row)
    hex_pids = re.findall(r'0x[0-9a-fA-F]+', text)
    result = set()
    for p in hex_pids:
        val = hex_to_int(p)
        if val > 4 and val != 4294967295: result.add(val)
    return result

def is_garbage(event_name, event_type, user_data):
    """
    ГЛАВНЫЙ ФИЛЬТР.
    Возвращает True, если строку нужно УДАЛИТЬ из отчета.
    """
    
    # 1. Убираем завершение операций ввода-вывода (шум)
    if "OperationEnd" in event_type or "SimpleOp" in event_type:
        return True
        
    # 2. УБИРАЕМ ЗАВЕРШЕНИЕ ПРОЦЕССА (Process End / Terminate)
    # Пользователь увидит только активность, но не смерть вируса.
    if event_name == "Process" and ("Terminate" in event_type or "End" in event_type):
        return True

    # 3. Убираем события FileIo с адресами памяти вместо путей
    if event_name == "FileIo" and (user_data.startswith("0x") or user_data.startswith("0X") or user_data.startswith("0xFFFF")):
        return True
        
    # 4. Убираем шум потоков
    if event_name == "Thread":
        return True
        
    # 5. Убираем выгрузку библиотек (UnLoad)
    if event_name == "Image" and "UnLoad" in event_type:
        return True

    return False

def detect_threat(event_name, user_data):
    """
    Определяет, является ли строка опасной (для подсветки на сайте).
    """
    data = user_data.lower()
    
    # 1. Shell / Скрипты
    if "powershell" in data:
        return "CRITICAL: Использование PowerShell"
    if "cmd.exe" in data:
        return "CRITICAL: Запуск командной строки"
    if "wscript" in data or "cscript" in data:
        return "CRITICAL: Запуск скриптов Windows"

    # 2. DLL
    if event_name == "Image" and "clr.dll" in data:
        return "WARNING: Загрузка .NET Runtime (подозрительно для C++)"

    # 3. Сеть
    if "TcpIp" in event_name:
        return "WARNING: Сетевая активность"

    # 4. Файлы
    if event_name == "FileIo":
        if ".exe" in data or ".bat" in data or ".vbs" in data:
            if "Create" in str(data) or "Write" in str(data):
                return f"HIGH: Создание исполняемого файла (Dropper)"
        if "system32" in data and "drivers" in data and "etc" in data:
            return "HIGH: Попытка модификации HOSTS"
        if "startup" in data:
            return "CRITICAL: Запись в Автозагрузку"

    return None

def main():
    print(f"[*] ЗАПУСК АНАЛИЗАТОРА (v9 NoDeath) ДЛЯ {TARGET_EXE}...")
    
    tracked_pids = set()
    rows_to_keep = []
    threats_log = []
    start_found = False
    
    # --- 1. ОБРАБОТКА CSV ---
    try:
        with open(CSV_INPUT, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f, skipinitialspace=True)
            headers = next(reader, None)
            
            for row_data in enumerate(reader): # enumerate дает (index, row)
                row = row_data[1]
                if len(row) < 10: continue
                
                event_name = row[0].strip()
                event_type = row[1].strip()
                pid_raw = row[9].strip()
                
                # Собираем данные (пути, аргументы)
                user_data_full = " ".join(row[15:]).strip().replace('"', '')
                full_row_str = str(row).lower()

                # A. ПОИСК НАЧАЛА
                if not start_found:
                    is_start = (event_name == "Process" and (event_type == "Start" or row[6] == "1"))
                    if "dcstart" in event_type.lower(): is_start = False

                    if is_start and TARGET_EXE.lower() in full_row_str:
                        pid = hex_to_int(pid_raw)
                        if pid > 0 and pid != 0xFFFFFFFF:
                            print(f"\n[+] ЗАПУСК ОБНАРУЖЕН: PID {pid}")
                            tracked_pids.add(pid)
                            start_found = True
                            # Сохраняем строку запуска (это всегда безопасно показать)
                            rows_to_keep.append(row) 
                    continue

                # B. СЛЕЖКА
                current_pid = hex_to_int(pid_raw)
                
                if current_pid in tracked_pids:
                    # Фильтр мусора (включая End/Terminate)
                    if is_garbage(event_name, event_type, user_data_full):
                        continue
                    
                    # Поиск угроз для отчета
                    threat_msg = detect_threat(event_name, user_data_full)
                    if threat_msg:
                        line_idx = len(rows_to_keep) + 1
                        print(f"   [!] Угроза (стр. {line_idx}): {threat_msg}")
                        threats_log.append({
                            "line_number": line_idx,
                            "event": event_name,
                            "details": user_data_full[:60] + "...",
                            "level": threat_msg.split(":")[0],
                            "msg": threat_msg
                        })

                    rows_to_keep.append(row)
                    
                    # Рост дерева процессов
                    if event_name == "Process" and (event_type == "Start" or row[6] == "1"):
                         if "dcstart" not in event_type.lower():
                            potential_childs = get_pids_from_row(row[10:])
                            for child in potential_childs:
                                if child not in tracked_pids and child != current_pid:
                                    print(f"[+] Новый процесс в дереве: {child}")
                                    tracked_pids.add(child)

    except FileNotFoundError:
        print("[-] trace.csv не найден.")
        return

    if not tracked_pids:
        print(f"[-] Не найден запуск {TARGET_EXE}.")
        return

    # --- 2. СОХРАНЕНИЕ ---
    print(f"\n[*] Итого событий: {len(rows_to_keep)}")
    
    # CSV
    with open(CSV_OUTPUT, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        if headers: writer.writerow(headers)
        writer.writerows(rows_to_keep)
    print(f"[OK] CSV: {CSV_OUTPUT}")

    # THREAT REPORT
    with open(REPORT_OUTPUT, 'w', encoding='utf-8') as f:
        json.dump(threats_log, f, indent=4, ensure_ascii=False)
    print(f"[OK] Threats: {REPORT_OUTPUT}")

    # JSON LOG (Clean)
    try:
        json_data = None
        for enc in ['utf-16', 'utf-8-sig', 'utf-8']:
            try:
                with open(JSON_INPUT, 'r', encoding=enc) as f:
                    json_data = json.load(f)
                break
            except: continue
            
        if json_data:
            json_kept = []
            for event in json_data:
                p = hex_to_int(event.get("PID", "0"))
                if p in tracked_pids:
                    evt_name = event.get("Event Name", "")
                    evt_type = event.get("Type", "")
                    evt_data = event.get("User Data", "")
                    
                    if not is_garbage(evt_name, evt_type, evt_data):
                        json_kept.append(event)
                        
            with open(JSON_OUTPUT, 'w', encoding='utf-8') as f:
                json.dump(json_kept, f, indent=4, ensure_ascii=False)
            print(f"[OK] JSON: {JSON_OUTPUT}")
    except: pass

def run_cleaner(target_exe, base_dir):
    global TARGET_EXE, CSV_INPUT, JSON_INPUT, CSV_OUTPUT, JSON_OUTPUT, REPORT_OUTPUT
    original_target_exe = TARGET_EXE
    original_csv_input = CSV_INPUT
    original_json_input = JSON_INPUT
    original_csv_output = CSV_OUTPUT
    original_json_output = JSON_OUTPUT
    original_report_output = REPORT_OUTPUT
    try:
        TARGET_EXE = target_exe
        CSV_INPUT = os.path.join(base_dir, "trace.csv")
        JSON_INPUT = os.path.join(base_dir, "trace.json")
        CSV_OUTPUT = os.path.join(base_dir, "clean_tree.csv")
        JSON_OUTPUT = os.path.join(base_dir, "clean_tree.json")
        REPORT_OUTPUT = os.path.join(base_dir, "threat_report.json")
        main()
    finally:
        TARGET_EXE = original_target_exe
        CSV_INPUT = original_csv_input
        JSON_INPUT = original_json_input
        CSV_OUTPUT = original_csv_output
        JSON_OUTPUT = original_json_output
        REPORT_OUTPUT = original_report_output

if __name__ == "__main__":
    main()