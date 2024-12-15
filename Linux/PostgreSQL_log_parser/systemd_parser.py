import re
from datetime import datetime
import subprocess

russian_to_english_months = {
    "янв": "Jan", "фев": "Feb", "мар": "Mar", "апр": "Apr",
    "май": "May", "июн": "Jun", "июл": "Jul", "авг": "Aug",
    "сен": "Sep", "окт": "Oct", "ноя": "Nov", "дек": "Dec"
}

# Регулярное выражение для разбора лога
log_pattern = re.compile(
    r"(?P<log_timestamp>\w{3} \d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\w+) "
    r"(?P<source>[^:]+): "
    r"(?P<message>.+)"
)

def parse_log_line(log_line):
    match = log_pattern.match(log_line)
    if match:
        log_data = match.groupdict()

        # Преобразуем log_timestamp с переводом месяца
        log_timestamp = log_data["log_timestamp"]

        # Замена русского месяца на английский
        for rus, eng in russian_to_english_months.items():
            log_timestamp = log_timestamp.replace(rus, eng)

        # Преобразование даты и времени в объект datetime и получение timestamp
        try:
            log_data["log_timestamp"] = datetime.strptime(log_timestamp, "%b %d %H:%M:%S").replace(year=datetime.now().year)

            return log_data

        except ValueError as e:
            print(f"systemd_logger: Ошибка при разборе даты и времени: {e}")
            return 0

    else:
        print("systemd_logger: Не удалось разобрать строку лога.")
        return 0

def systemd_logger(log_queue):
    # Запускаем команду journalctl для получения логов PostgreSQL
    process = subprocess.Popen(
        ['journalctl', '-f', '-u', 'postgresql.service', '--since', 'now'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    print("Начинаем отслеживать логи для postgresql.service...")

    # Чтение и вывод каждой строки лога
    try:
        for line in process.stdout:
            # Разбор строки лога (по вашему шаблону)
            log_data = parse_log_line(line.strip())

            if log_data:
                result = log_data
                result["id"] = 1
                log_queue.put(result)


    # хз надо ли это тут
    # тут ловим ctrl C
    except KeyboardInterrupt:
        print("Завершение работы скрипта...")
        process.kill()
