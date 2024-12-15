def ror(value, shift, bits=32):
    # Функция для циклического сдвига вправо
    return ((value >> shift) | (value << (bits - shift))) & (2 ** bits - 1)


def ascii_sum_to_hex_with_ror_xor(input_string):
    ascii_sum = 0
    for i, char in enumerate(input_string):
        i += 1
        # Шаг 1: прибавляем ASCII-код символа
        ascii_sum += ord(char)

        # Шаг 2: выполняем циклический сдвиг вправо на i позиций
        ascii_sum = ror(ascii_sum, i)

        # Шаг 3: снова прибавляем ASCII-код символа
        ascii_sum += ord(char)

        # Шаг 4: выполняем XOR с номером итерации
        ascii_sum ^= i

    # Преобразуем итоговую сумму в шестнадцатеричное представление
    hex_value = hex(ascii_sum)
    return hex_value

def ascii_sum_to_hex(input_string):
    # Считаем сумму ASCII-кодов символов
    ascii_sum = sum(ord(char) for char in input_string)
    # Преобразуем сумму в шестнадцатеричное представление
    hex_value = hex(ascii_sum)
    return hex_value

def xor_string(input_string):
    # Преобразуем строку в байты с использованием Windows-1251
    byte_values = input_string.encode('windows-1251')

    # Применяем XOR с 0x39 для каждого байта
    xor_values = [byte ^ 0x39 for byte in byte_values]

    # Форматируем вывод как 0xNN (двухзначный формат)
    xor_hex_values = [f"0x{value:02x}" for value in xor_values]

    return ', '.join(xor_hex_values)


# Пример использования
# print(f"Результат XOR: {xor_string('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')}")

# Пример использования
print("Сумма ASCII-кодов в hex:", ascii_sum_to_hex_with_ror_xor("go"))  # для своих ф. надо значение переворачивать
print("Сумма ASCII-кодов в hex:", ascii_sum_to_hex_with_ror_xor("start"))  # для своих ф. надо значение переворачивать
print("Сумма ASCII-кодов в hex:", ascii_sum_to_hex_with_ror_xor("need"))  # для своих ф. надо значение переворачивать
#
# print(ascii_sum_to_hex("1.exe"))



# Определение функций для имитации операций на 32-битных регистрах

def ror(value, shift):
    # Выполняет циклический сдвиг вправо (ROR)
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF

# RVA
start_text = 0x00004000
exit = 0x00004b50           # смещения от прерыдущей функции
reg = [
    [0x25400080, 0x00],   # exit
    [0x24000085, 0x50],   # end

    [0x2000008B, 0x10],   # pwd
    [0x600000a0, 0x50],   # cd
    [0x2f06007c, 0x30],   # mkdir

    [0x000000b8, 0x30],   # ps
    [0x98000090, 0x200],   # run
    [0x34000079, 0x50],    # term

    [0xc10e7404, 0x80],    # addUser
    [0xc10e8974, 0xA0],    # delUser
]

# Вывод RVA команд
for g in reg:
    exit += g[1]
    g[1] = exit
    print(f"Результат: {g[1]:#010x}")

print()

# Шифрование смещения
for i in reg:
    # Инициализация значений esi и ecx
    esi = i[1] - start_text  # смещение от начала секции
    ecx = i[0]  # крипт название

    # Реализация алгоритма
    esi += ecx  # add esi, ecx
    esi = ror(esi, ecx & 0x1F)  # ror esi, cl (кратность сдвига ограничена 5 битами, так как 32 бита)
    esi ^= ecx  # xor esi, ecx

    # Печать результата
    print(f"Результат: {esi:#010x}")  # Вывод в формате 0x...

