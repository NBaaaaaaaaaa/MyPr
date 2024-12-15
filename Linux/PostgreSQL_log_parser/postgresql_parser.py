import re
from datetime import datetime
import subprocess

log_pattern = re.compile(
        r'^(?P<log_timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?)\s+'
        r'(?P<timezone>\w+)\s+'
        r'\[(?P<pid>\d+)\]\s+'
        r'(?:\s*(?P<user_db>[^ ]+)\s+)?'
        r'(?P<level>\w+):\s+'
        r'(?P<message>.*)$'
    )

def get_log_filename():
    # Получаем текущий день недели в сокращённом формате (например, 'Fri', 'Mon')
    current_day = datetime.now().strftime('%a')
    # Формируем имя лог-файла PostgreSQL на основе дня недели
    log_filename = f'/var/lib/postgresql/11/main/pg_log/postgresql-{current_day}.log'
    return log_filename

def parse_log_line(log_line):
    match = log_pattern.match(log_line)
    if match:
        log_data = match.groupdict()

        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                log_data["log_timestamp"] = datetime.strptime(log_data["log_timestamp"], fmt)
                break
            except ValueError as e:
                if fmt == "%Y-%m-%d %H:%M:%S":
                    print(f"postgresql_logger: Ошибка при разборе даты и времени: {e}")
                    return 0

        return log_data

    else:
        print("postgresql_logger: Не удалось разобрать строку лога.")
        print(log_line)
        return 0

def postgresql_logger(log_queue):
    log_filename = get_log_filename()

    try:
        # Запускаем tail -f для отслеживания лог-файла PostgreSQL
        process = subprocess.Popen(
            ['tail', '-n', '0', '-f', log_filename],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True  # Это эквивалент universal_newlines=True, делает вывод в строковом формате
        )

        print(f"Чтение логов из файла: {log_filename}")

        # Чтение новых строк в реальном времени
        for line in process.stdout:
            log_data = parse_log_line(line)

            if log_data and log_data["user_db"] != "logger@loggerdb":
                result = log_data
                result["id"] = 2
                log_queue.put(result)

    except FileNotFoundError:
        print(f"Файл {log_filename} не найден.")
    except Exception as e:
        print(f"Ошибка при чтении файла лога: {e}")

