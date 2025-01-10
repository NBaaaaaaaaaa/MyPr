// gcc -o proc_inj proc_inj.c p_methods.c -lssl -lcrypto

#include <openssl/evp.h>
#include <dirent.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>  
#include <sys/stat.h> 
#include <ctype.h>

#include "common.h"


unsigned char payload32[] = {
    0x90, 0x90, 0x9c, 0x50, 0x53, 0x51, 0x52, 0x57, 
    0x56, 0x6a, 0x00, 0x68, 0x77, 0x6f, 0x72, 0x6b,
    0x68, 0x69, 0x74, 0x73, 0x20, 0xbb, 0x01, 0x00, 
    0x00, 0x00, 0x89, 0xe1, 0xba, 0x0a, 0x00, 0x00, 
    0x00, 0xb8, 0x04, 0x00, 0x00, 0x00, 0xcd, 0x80, 
    0x83, 0xc4, 0x0c, 0x5e, 0x5f, 0x5a, 0x59, 0x5b, 
    0x58, 0x9d    
};

unsigned char payload64[] = {
    0x90, 0x90, 0x9C, 0x50, 0x53, 0x51, 0x52, 0x57, 
    0x56, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 
    0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 
    0x57, 0x6A, 0x00, 0x48, 0xB8, 0x69, 0x74, 0x73, 
    0x20, 0x77, 0x6F, 0x72, 0x6B, 0x50, 0xBF, 0x01, 
    0x00, 0x00, 0x00, 0x48, 0x89, 0xE6, 0xBA, 0x0A, 
    0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 
    0x0F, 0x05, 0x48, 0x83, 0xC4, 0x10, 0x41, 0x5F, 
    0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 
    0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5E, 0x5F, 
    0x5A, 0x59, 0x5B, 0x58, 0x9D
};

// Хэши файлов, что патчить можно
const char* known_hashes[] = {
    "c8f9c2dd232704e1f07e53be7e95711416a1db6d2b89f9e7d8b8612bf29e9046",     // test_file32
    "1c70da668d251979f664a74c276a4a34ffca79db22407a29f5e77436f90bf54b",     // test_file64
    "ca48cb97f4288cb15cd6bcdaca11b63e4c477e4ac014f6e24d57694eeb1a2643",     // test_file32s
    "c8f9c2dd232704e1f07e53be7e95711416a1db6d2b89f9e7d8b8612bf29e9046",     // test_file64s
    "62e9c413744f825cbf23173e8e06592801478ffd51b7727e24cd659d13c3870a",     // rand32
    "c5c30ad55c0a9ec4a8c296f8220228549f9d2de20a5516e7fdf64350276acf42",     // rand64
    "bac42cafb9cae10b84bd8985aa230d6406cd61b68ebe2293bc1f23557f3a99d2",     // rand32s
    "1393169364c15b2a96a2644762be93977a98789cc857b41600dd576cbb672c38",     // rand64s
    NULL
};

// Методы перехода на полезную нагрузку
enum Ptype {m_ip, m_cur_inst, m_got, m_fini, m_fini_array};

// Функция вычисления SHA-256 хэша файла
// IN *file_path - адрес названия файла
// OUT *hash_str - адрес хэша файла
// IN hash_str_size - размер хэша
int compute_sha256(const char *file_path, char *hash_str, size_t hash_str_size) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned char buffer[4096];
    unsigned int hash_len = 0;

    FILE *file = fopen(file_path, "rb");
    if (file) {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            fprintf(stderr, "  [!] compute_sha256: EVP_MD_CTX_new().\n");
            fclose(file);
            return 1;
        }

        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
            fprintf(stderr, "  [!] compute_sha256: EVP_DigestInit_ex().\n");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return 1;
        }

        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
                fprintf(stderr, "  [!] compute_sha256: EVP_DigestUpdate.\n");
                EVP_MD_CTX_free(mdctx);
                fclose(file);
                return 1;
            }
        }

        if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
            fprintf(stderr, "  [!] compute_sha256: EVP_DigestFinal_ex.\n");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return 1;
        }

        fclose(file);
        EVP_MD_CTX_free(mdctx);

        // Преобразовываем бинарный хэш в строку
        for (unsigned int i = 0; i < hash_len; i++) {
            snprintf(hash_str + (i * 2), hash_str_size - (i * 2), "%02x", hash[i]);
        }
        
        return 0;
    }

    return 1;
}

// Функция сравнения хэша с известными хэшами
int is_hash_known(const char *hash_str) {
    for (const char **known_hash = known_hashes; *known_hash != NULL; known_hash++) {
        if (strcmp(hash_str, *known_hash) == 0) {
            return 1; 
        } 
    }
    return 0; 
}

// Функция получения адреса загрузки 
// IN *exe_path - путь до файла /proc/[pid]/exe
// IN *pi - адрес структуры Process_info
// OUT pi->process_addr - адрес загрузки
int get_process_addr(char *exe_path, struct Process_info *pi) {
    // Считывание символьной ссылки
    char file_path[1024];
    ssize_t file_path_len = readlink(exe_path, file_path, sizeof(file_path)-1);
    if (file_path_len == -1) {
        perror("  [!] get_process_addr: readlink().");
        return 1;
    }
    
    file_path[file_path_len] = '\0';  
    printf("  [+] Символьная ссылка указывает на: %s\n", file_path);
    
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pi->pid);

    FILE *file = fopen(maps_path, "r");
    if (file == NULL) {
        fprintf(stderr, "  [!] get_process_addr: fopen(): %s.\n", maps_path);
        return 1;
    }

    char line[1024];                                                // Буфер для чтения строки
    bool is_process_addr = false;                                   // Записали или нет адрес загрузки
    
    while (fgets(line, sizeof(line), file) != NULL) {               // Читаем построчно
        char address_str[16];

        // Извлекаем подстроку
        if (sscanf(line, "%30[^-]", address_str) != 1) {
            perror("  [!] get_process_addr: sscanf().");
            return 1;
        }

        if (strstr(line, file_path) != NULL && !is_process_addr) {
            pi->process_addr = strtoul(address_str, NULL, 16);
            is_process_addr = true;
        } 
    }

    fclose(file);                                                   // Закрываем файл
    return 0;
}

// Функция вставки нагрузки
// IN *pi - адрес структуры Process_info
// OUT pi->ei_class - разрядность файла
// OUT pi->pic - позиционно зависимый код или нет
// OUT pi->fi32/64.e_phoff - RAW смещение программного заголовка
// OUT pi->e_phentsize - размер одного программного заголовка
// OUT pi->e_phnum - количество программных заголовков
// OUT pi->fi32/64.addr_free - RVA/VA нагрузки
// OUT pi->payload_size - размер нагрузки
int insert_payload(struct Process_info *pi) {
    // Чтение разрядности файла
    if (pread(pi->mem_fd, &pi->ei_class, sizeof(pi->ei_class), pi->process_addr + 0x04) == -1) {
        perror("  [!] insert_payload: pread: pi->ei_class");
        return 1;
    }

    // Чтение типа файла
    uint16_t e_type;
    if (pread(pi->mem_fd, &e_type, sizeof(e_type), pi->process_addr + 0x10) == -1) {
        perror("  [!] insert_payload: pread: e_type");
        return 1;
    }

    if (e_type == 0x02) {           // exec
        pi->pic = false;        
    } else if (e_type == 0x03) {    // dyn
        pi->pic = true;
    } else {
        fprintf(stderr, "  [!] insert_payload: Тип файла не подходит.\n");
        return 1;
    }

    // Чтение информации о программных заголовках
    if (pi->ei_class == 0x01) {
        if (pread(pi->mem_fd, &pi->fi32.e_phoff, sizeof(pi->fi32.e_phoff), pi->process_addr + 0x1c) == -1) {
            perror("  [!] insert_payload: pread: pi->fi32.e_phoff.");
            return 1;
        }
        if (pread(pi->mem_fd, &pi->e_phentsize, sizeof(pi->e_phentsize), pi->process_addr + 0x2a) == -1) {
            perror("  [!] insert_payload: pread: pi->e_phentsize.");
            return 1;
        }
        if (pread(pi->mem_fd, &pi->e_phnum, sizeof(pi->e_phnum), pi->process_addr + 0x2c) == -1) {
            perror("  [!] insert_payload: pread: pi->e_phnum.");
            return 1;
        }

    } else if (pi->ei_class == 0x02) {
        if (pread(pi->mem_fd, &pi->fi64.e_phoff, sizeof(pi->fi64.e_phoff), pi->process_addr + 0x20) == -1) {
            perror("  [!] insert_payload: pread: pi->fi32.e_phoff.");
            return 1;
        }
        if (pread(pi->mem_fd, &pi->e_phentsize, sizeof(pi->e_phentsize), pi->process_addr + 0x36) == -1) {
            perror("  [!] insert_payload: pread: pi->e_phentsize.");
            return 1;
        }
        if (pread(pi->mem_fd, &pi->e_phnum, sizeof(pi->e_phnum), pi->process_addr + 0x38) == -1) {
            perror("  [!] insert_payload: pread: pi->e_phnum.");
            return 1;
        }

    } else {
        fprintf(stderr, "  [!] Ошибка: Неизвестное значение EI_CLASS.\n");
        return 1;
    }

    // Поиск сегмента под нагрузку и размещение ее в нем
    for (uint16_t ph = 0; ph < pi->e_phnum; ph++ ) {
        // 32 битное приложение
        if (pi->ei_class == 0x01) {
            pi->fi32.e_phoff += pi->e_phentsize;

            uint32_t p_type;
            uint32_t p_flags;
            
            // Чтение типа сегмента
            if (pread(pi->mem_fd, &p_type, sizeof(p_type), pi->process_addr + pi->fi32.e_phoff) == -1) {
                perror("  [!] insert_payload: pread: p_type.");
                return 1;
            }

            // Чтение флагов сегмента
            if (pread(pi->mem_fd, &p_flags, sizeof(p_flags), pi->process_addr + pi->fi32.e_phoff + 0x18) == -1) {
                perror("  [!] insert_payload: pread: p_flags.");
                return 1;
            }

            // PT_LOAD and PF_X
            if (p_type == 0x01 && p_flags & 0x01) {
                // Чтение vaddr следующего сегмента
                uint32_t p_vaddr_next;     
                if (pread(pi->mem_fd, &p_vaddr_next, sizeof(p_vaddr_next), pi->process_addr + pi->fi32.e_phoff + pi->e_phentsize + 0x08) == -1) {
                    perror("  [!] insert_payload: pread: p_vaddr_next.");
                    return 1;
                }

                if (p_vaddr_next % 0x1000 == 0) {  
                    // Чтение vaddr сегмента
                    uint32_t p_vaddr;   
                    if (pread(pi->mem_fd, &p_vaddr, sizeof(p_vaddr), pi->process_addr + pi->fi32.e_phoff + 0x08) == -1) {
                        perror("  [!] insert_payload: pread: p_vaddr_next.");
                        return 1;
                    }

                    // Чтение размера сегмента
                    if (pread(pi->mem_fd, &pi->fi32.addr_free, sizeof(pi->fi32.addr_free), pi->process_addr + pi->fi32.e_phoff + 0x10) == -1) {
                        perror("  [!] insert_payload: pread: pi->fi32.addr_free.");
                        return 1;
                    }
                    pi->fi32.addr_free += p_vaddr;          // Vaddr свободного места в сегменте

                    pi->payload_size = sizeof(payload32);
                    // Влезает ли нагрузка в конец сегмента или нет
                    if (pi->fi32.addr_free + pi->payload_size + 0x05 <= p_vaddr_next) {                         // Проверка, влезает ли нагрузка или нет
                        // Копируем нагрузку
                        if (pi->pic) {
                            if (pwrite(pi->mem_fd, payload32, pi->payload_size, pi->process_addr + pi->fi32.addr_free) == -1) {
                                perror("  [!] insert_payload: pwrite: payload32.");
                                return 1;
                            }
                            printf("  [+] Нагрузка распологается по адресу 0x%08lx\n", pi->process_addr + pi->fi32.addr_free);

                        } else {
                            if (pwrite(pi->mem_fd, payload32, pi->payload_size, pi->fi32.addr_free) == -1) {
                                perror("  [!] insert_payload: pwrite: payload32.");
                                return 1;
                            }
                            printf("  [+] Нагрузка распологается по адресу 0x%08lx\n", pi->fi32.addr_free);
                        }

                        break;
                    }
                }
            }
        // 64 битное приложение
        } else {
            pi->fi64.e_phoff += pi->e_phentsize;
            
            uint32_t p_type;
            uint32_t p_flags;

            // Чтение типа сегмента
            if (pread(pi->mem_fd, &p_type, sizeof(p_type), pi->process_addr + pi->fi64.e_phoff) == -1) {
                perror("  [!] insert_payload: pread: p_type.");
                return 1;
            }
            // Чтение флагов сегмента
            if (pread(pi->mem_fd, &p_flags, sizeof(p_flags), pi->process_addr + pi->fi64.e_phoff + 0x04) == -1) {
                perror("  [!] insert_payload: pread: p_flags.");
                return 1;
            }

            // PT_LOAD and PF_X
            if (p_type == 0x01 && p_flags & 0x01) {
                // Чтение vaddr следующего сегмента
                uint64_t p_vaddr_next;     
                if (pread(pi->mem_fd, &p_vaddr_next, sizeof(p_vaddr_next), pi->process_addr + pi->fi64.e_phoff + pi->e_phentsize + 0x10) == -1) {
                    perror("  [!] insert_payload: pread: p_vaddr_next.");
                    return 1;
                }

                if (p_vaddr_next % 0x1000 == 0) {  
                    // Чтение vaddr сегмента
                    uint64_t p_vaddr; 
                    if (pread(pi->mem_fd, &p_vaddr, sizeof(p_vaddr), pi->process_addr + pi->fi64.e_phoff + 0x10) == -1) {
                        perror("  [!] insert_payload: pread: p_vaddr_next.");
                        return 1;
                    }

                    // Чтение размера сегмента
                    if (pread(pi->mem_fd, &pi->fi64.addr_free, sizeof(pi->fi64.addr_free), pi->process_addr + pi->fi64.e_phoff + 0x20) == -1) {
                        perror("  [!] insert_payload: pread: pi->fi64.addr_free.");
                        return 1;
                    }
                    pi->fi64.addr_free += p_vaddr;          // Vaddr свободного места в сегменте

                    pi->payload_size = sizeof(payload64);
                    // Влезает ли нагрузка в конец сегмента или нет
                    if (pi->fi64.addr_free + pi->payload_size + 0x14 <= p_vaddr_next) {                         // Проверка, влезает ли нагрузка или нет
                        // Копируем нагрузку
                        if (pi->pic) {
                            if (pwrite(pi->mem_fd, payload64, pi->payload_size, pi->process_addr + pi->fi64.addr_free) == -1) {
                                perror("  [!] insert_payload: pwrite: payload64.");
                                return 1;
                            }

                            printf("  [+] Нагрузка распологается по адресу 0x%08lx\n", pi->process_addr + pi->fi64.addr_free);
                        } else {
                            if (pwrite(pi->mem_fd, payload64, pi->payload_size, pi->fi64.addr_free) == -1) {
                                perror("  [!] insert_payload: pwrite: payload64.");
                                return 1;
                            }

                            printf("  [+] Нагрузка распологается по адресу 0x%08lx\n", pi->fi64.addr_free);
                        }

                        break;
                    }
                }
            }
        }

    }

    return 0;
}

// Функция вставки перехода на нагрузку
// IN *pi - адрес структуры Process_info
void go_to_payload(struct Process_info *pi){
    int p_method;
    
    // Вывод меню
    do {
        printf("\n  Методы перехода на вставленную нагрузку:\n");
        printf("  1) Замена содержимого регистра ip\n");
        printf("  2) Замена текущей инструкции\n");
        printf("  3) Замена первого адреса функции в .got.plt\n");
        printf("  4) Замена .fini\n");
        printf("  5) Замена первого элемента в .fini_array\n");
        printf("  6) Пропустить\n");
        printf("  > ");

        if (scanf("%d", &p_method) != 1) {
            printf("  [!] Ошибка ввода!\n");
            return;
        }

        switch (--p_method) {
            case m_ip:
                p_m_ip(pi);
                return;

            case m_cur_inst:
                p_m_cur_inst(pi);
                return;

            case m_got:
                p_m_got_plt(pi);
                return;

            case m_fini:
                p_m_fini(pi);
                return;

            case m_fini_array:
                p_m_fini_array(pi);
                return;

            case 5:     // Пропуск
                return;

            default:
                printf("  [!] Неизвестный метод\n");
                break;
        }

    } while (true);
}

int main() {
    struct Process_info pi;

    DIR *dir = opendir("/proc");
    if (dir == NULL) {
        perror("  [!] main: opendir: /proc.");
        return 1;
    }

    int process_count = 0;         // Счетчик корректных процессов
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Пропкаем ".", "..", и нечисловые папки
        if (entry->d_name[0] == '.' || !isdigit(entry->d_name[0])) {
            continue;
        }

        pid_t pid = atoi(entry->d_name);

        char exe_path[20];
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
        
        char hash_str[EVP_MAX_MD_SIZE * 2 + 1] = {0};
        if (!compute_sha256(exe_path, hash_str, sizeof(hash_str))){     // Вычисление хеша
            if (is_hash_known(hash_str)){                               // Совпадает ли хеш
                process_count++;  
                pi.pid = pid;

                printf("\n%d) PID = %d\n", process_count, pi.pid);

                // Отправляем сигнал SIGSTOP процессу
                if (kill(pi.pid, SIGSTOP) == -1) {
                    perror("  [!] main: kill: SIGSTOP.");
                    return 1;
                }
                printf("  [+] Процесс %d успешно приостановлен (SIGSTOP)\n", pi.pid);
                
                // Получаем адрес загрузки
                if (get_process_addr(exe_path, &pi)){
                    return 1;
                }
                
                char mem_path[256];
                snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pi.pid);

                // Открываем файл памяти процесса
                pi.mem_fd = open(mem_path, O_RDWR);
                if (pi.mem_fd == -1) {
                    perror("  [!] main: open: /proc/<pi.pid>/mem");
                    return 1;
                }

                if (insert_payload(&pi)){
                    fprintf(stderr, "Ошибка вставки нагрузки в /proc/%d/mem", pi.pid);
                    close(pi.mem_fd);
                    return 1;
                }

                // Вставка перехода на нагрузку
                go_to_payload(&pi);

                close(pi.mem_fd);

                // Отправляем сигнал SIGCONT процессу
                if (kill(pi.pid, SIGCONT) == -1) {
                    perror("\n  [!] main: kill: SIGCONT");
                    return 1;
                }
                printf("\n  [+] Процесс %d успешно возобновлен (SIGCONT)\n", pi.pid);
            }
        }
    }

    closedir(dir);

    if (!process_count) {
        printf("  [!] Подходящих процессов не найдено.\n");
    }

    return 0;
}
