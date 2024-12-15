import psycopg2
from psycopg2 import sql
from psycopg2 import OperationalError, InterfaceError

import time

from systemd_parser import systemd_logger
from postgresql_parser import postgresql_logger

import queue
import threading

class PSQL:
    __conn_params = {
        "dbname": "loggerdb",
        "user": "logger",
        "password": "logger123",
        "host": "localhost",
        "port": 5432
    }

    __insert_queries = {
        1: """
INSERT INTO systemd_logs (log_timestamp, host, source, message)
VALUES (%s, %s, %s, %s);
""",
        2:"""
INSERT INTO postgresql_logs (log_timestamp, pid, user_db, level, message)
VALUES (%s, %s, %s, %s, %s);
"""
    }

    __RETRY_INTERVAL = 5  # Интервал повторных попыток в секундах
    __MAX_RETRIES = 5  # Максимальное количество попыток подключения
    __conn = None
    __cursor = None

    def __init__(self):
        self.connect_to_db()

    # Метод подключения к бд
    def connect_to_db(self):
        for attempt in range(self.__MAX_RETRIES):
            try:
                self.__conn = psycopg2.connect(**self.__conn_params)
                self.__cursor = self.__conn.cursor()

                print("Успешное подключение к базе данных")
                return

            except OperationalError as e:
                print(f"Ошибка подключения: {e}. Попытка {attempt + 1} из {self.__MAX_RETRIES}")
                time.sleep(self.__RETRY_INTERVAL)
        raise Exception("Не удалось подключиться к базе данных после нескольких попыток")

    # метод вставки лога в таблицу
    def insert_log(self, log_data):
        iq_id = log_data["id"]
        del log_data["id"]

        for i in range(2):
            try:
                insert_query = sql.SQL(self.__insert_queries[iq_id])

                if iq_id == 1:
                    self.__cursor.execute(insert_query,
                                   (log_data['log_timestamp'], log_data['host'], log_data['source'], log_data['message']))
                elif iq_id == 2:
                    self.__cursor.execute(insert_query,
                                   (log_data['log_timestamp'], log_data['pid'], log_data['user_db'], log_data['level'],log_data['message']))

                self.__conn.commit()
                break

            except (OperationalError, InterfaceError) as e:
                print(f"Ошибка выполнения запроса: {e}.")
                self.connect_to_db()


    def __del__(self):
        self.__conn.close()
        self.__cursor.close()



psql = PSQL()

# Функция для записи логов в базу данных
def insert_log_into_db(log_queue):
    while True:
        log_data = log_queue.get()  # Получаем строку лога из очереди

        psql.insert_log(log_data)
            


if __name__=="__main__":
    log_queue = queue.Queue()

    # запуск потока логгирования systemd
    systemd_th = threading.Thread(target=systemd_logger, args=(log_queue,))
    systemd_th.start()
    # запуск потока логгирования postgresql
    postgresql_th = threading.Thread(target=postgresql_logger, args=(log_queue,))
    postgresql_th.start()

    # основной поток ждет строки из очереди
    insert_log_into_db(log_queue)

