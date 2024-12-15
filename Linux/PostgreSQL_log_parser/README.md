Парсер логов systemd и логов PostgreSQL.

# Версии ПО
1. Python = 3.7.3
2. PostgreSQL = 11.22
3. OS = Astra Linux, 6.1.90-1-generic

# Зависимоти
1. psycopg2-binary = 2.9.9
2. python3-systemd

# Алгоритм работы
## main.py
1. Подключается к бд: loggerdb;
1. Запускает два потока: systemd_logger, postgresql_logger;
1. Ждет лог в очереди;
1. Заносит логи в таблицы: systemd_logs, postgresql_logs.

## systemd_parser.py и postgresql_parser.py
1. Считывают лог;
1. Обрабатывают лог;
1. Помещают лог в очередь.

