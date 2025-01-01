#include <stdlib.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>

#include "p_methods.h"
#include "common.h"

unsigned char payload32[] = {
    0x9c, 0x50, 0x53, 0x51, 0x52, 0x57, 0x56, 0x6a, 
    0x00, 0x68, 0x77, 0x6f, 0x72, 0x6b, 0x68, 0x69, 
    0x74, 0x73, 0x20, 0xbb, 0x01, 0x00, 0x00, 0x00, 
    0x89, 0xe1, 0xba, 0x0a, 0x00, 0x00, 0x00, 0xb8, 
    0x04, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x83, 0xc4, 
    0x0c, 0x5e, 0x5f, 0x5a, 0x59, 0x5b, 0x58, 0x9d    
};

unsigned char payload64[] = {
    0x9C, 0x50, 0x53, 0x51, 0x52, 0x57, 0x56, 0x41,
    0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41,
    0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x6A,
    0x00, 0x48, 0xB8, 0x69, 0x74, 0x73, 0x20, 0x77,
    0x6F, 0x72, 0x6B, 0x50, 0xBF, 0x01, 0x00, 0x00,
    0x00, 0x48, 0x89, 0xE6, 0xBA, 0x0A, 0x00, 0x00,
    0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05,
    0x48, 0x83, 0xC4, 0x10, 0x41, 0x5F, 0x41, 0x5E,
    0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A,
    0x41, 0x59, 0x41, 0x58, 0x5E, 0x5F, 0x5A, 0x59,
    0x5B, 0x58, 0x9D
};

// Хэши файлов, что патчить можно
const char* known_hashes[] = {
    "95904639feafac849ca90539005061929da1b7458992c30e4d98a83463bf6752",     // sum1-10_32
    "88525e861a8287c59af3c45d4634a561bf9da0dea8864ffa3960aa9b895183c7",     // sum1-10_64
    "079a9ba6dcb5c4a8f624eb8792b67d44f924666f1580dbc451ddcc962d3bc96b",     // rand_arr_32
    "d8f38af7a4c3415be19c2c037920eef2557522c2696a8997c716db2dba4e11a8",     // rand_arr_64
    "95aec92a4f50114a0ec5fc2f3d3cbc49c93f1ef4492e2a5225992c4e7fa6794d",     // file32
    "8724f1f6844c07c45d7a5c5ee88257ed5c9be05e46562a89dc868ee3af2f73ba",     // file64
    NULL
};

// Методы перехода на полезную нагрузку
enum Ptype {m_e_entry, m_init, m_init_array, m_fini, m_fini_array, m_plt};

jmp_buf env;

// Функция вычисления SHA-256 хэша файла
// IN *file_path - адрес названия файла
// OUT *hash_str - адрес хэша файла
// IN hash_str_size - размер хэша
int compute_sha256(const char *file_path, char *hash_str, size_t hash_str_size) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned char buffer[4096];
    unsigned int hash_len = 0;

    FILE *file = fopen(file_path, "rb");
    if (!file) {
        fprintf(stderr, "[!] Не удалось открыть файл: %s.\n", file_path);
        return 0;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "[!] Ошибка создания контекста для хэширования.\n");
        fclose(file);
        return 0;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "[!] Ошибка инициализации алгоритма SHA-256.\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 0;
    }

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            fprintf(stderr, "[!] Ошибка обновления хэша.\n");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return 0;
        }
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        fprintf(stderr, "[!] Ошибка завершения хэширования.\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 0;
    }

    fclose(file);
    EVP_MD_CTX_free(mdctx);

    // Преобразовываем бинарный хэш в строку
    for (unsigned int i = 0; i < hash_len; i++) {
        snprintf(hash_str + (i * 2), hash_str_size - (i * 2), "%02x", hash[i]);
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

// Обработчик сигнала сегментационной ошибки
void sigsegv_handler(int sig) {
    // Восстанавливаем выполнение программы после ошибки
    longjmp(env, 1);  // Переводит выполнение программы в точку, где был вызван setjmp
}

// Функция добавления переходов на полезнкую нагрузку
// IN *file_data - адрес данных файла в памяти с нагрузкой
// IN *file_size - адрес размера файла
// IN *fi - адрес структуры
void add_link_to_payload(const unsigned char *const file_data, const size_t *const file_size, struct File_info *const fi) {
    for (enum Ptype ptype = m_e_entry; ptype <= m_plt; ptype++) {
        // Выделяем ещё один блок памяти для вставки перехода на нагрузку
        unsigned char *new_data = (unsigned char *)malloc(*file_size);
        if (new_data == NULL) {
            perror("[!] Ошибка malloc");
            return;
        }

        memcpy(new_data, file_data, *file_size);                    // Копируем данные с содержанием нагрузки

        // Реализовываем различные переходы на нагрзку
        switch (ptype)
        {
            case m_e_entry:
                printf("\n> Метод изменения адреса точки входа\n");
                fm_e_entry(new_data, file_size, fi);
                break;

            case m_init:
                printf("\n> Метод изменения адреса init в dynamic\n");
                fm_init_fini(new_data, file_size, fi, (uint8_t)0x0c);
                break;

            case m_init_array:
                printf("\n> Метод изменения первого адреса в init_array\n");
                fm_init_fini_array(new_data, file_size, fi, false);
                break;

            case m_fini:
                printf("\n> Метод изменения адреса fini в dynamic\n");
                fm_init_fini(new_data, file_size, fi, (uint8_t)0x0d);
                break;

            case m_fini_array:
                printf("\n> Метод изменения первого адреса в fini_array\n");
                fm_init_fini_array(new_data, file_size, fi, true);
                break;

            case m_plt:
                printf("\n> Метод изменения адреса импортируемой функции (plt)\n");
                fm_plt(new_data, file_size, fi);
                break;

            default:
                fprintf(stderr, "[!] Ошибка: Неизвестный метод внедрения\n");
                break;
        }
        
        free(new_data);         // Освобождаем память
    }
}

// Функция создания директорий
// IN *fi - адрес структуры
// OUT fi->file_dir - название директории под результаты патчинга
void create_directories(struct File_info *const fi) {
    // Создаем папку results
    const char *results_dir = "results";
    if (mkdir(results_dir, 0755) == -1 && errno != EEXIST) {
        perror("[!] Ошибка создания директории под результаты.");
        return;
    }

    // Создаем путь для папки внутри results
    char file_dir[256];
    snprintf(file_dir, sizeof(file_dir), "%s/%s", results_dir, fi->file_path);

    // Создаем папку с именем fi->file_path
    if (mkdir(file_dir, 0755) == -1 && errno != EEXIST) {
        perror("[!] Ошибка создания директории под файл.");
        return;
    }

    printf("[+] Директория под файл успешно создана: %s\n", file_dir);

    fi->file_dir = strdup(file_dir);                                        // Выделяем память под директорию файла
}

// Функция патчинга файла
// IN *file_path - адрес строки названия файла
// IN *file_size - адрес значения размера файла
void patch_file(const char *const file_path, const size_t *const file_size) {
    printf("Патчинг файла: %s.\n", file_path);
    struct File_info fi;
    fi.file_path = file_path;                                               // Сохраняем название файла

    create_directories(&fi);                                                // Создаем директрии под файлы

    signal(SIGSEGV, sigsegv_handler);                                       // Устанавливаем обработчик для сигнала сегментационной ошибки

    // Открываем файл для чтения
    int fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        perror("[!] Ошибка: open");
        free(fi.file_dir);
        return;
    }

    // Выделяем память для данных файла
    unsigned char *file_data = (unsigned char *)malloc(*file_size);
    if (file_data  == MAP_FAILED) {
        perror("[!] Ошибка: malloc");
        close(fd);
        free(fi.file_dir);
        return;
    }

    // Читаем данные файла в выделенную память
    if (read(fd, file_data, *file_size) != *file_size) {
        perror("[!] Ошибка: read");
        free(file_data);
        close(fd);
        free(fi.file_dir);
        return;
    }

    // Устанавливаем точку восстановления с помощью setjmp
    if (setjmp(env) == 0) {
        // Парсим файловый заголовок
        if (*(uint16_t *)(file_data + 0x10) == 0x02) {
            fi.pic = false;
        } else if (*(uint16_t *)(file_data + 0x10) == 0x03) {
            fi.pic = true;
        } else {
            printf("[!] Неверный тип файла");
            return;
        }

        if (file_data[4] == 0x01) {
            fi.ei_class = 0x01;
            fi.fi32.e_entry = *(uint32_t *)(file_data + 0x18);
            fi.fi32.e_phoff = *(uint32_t *)(file_data + 0x1C);
            fi.fi32.e_shoff = *(uint32_t *)(file_data + 0x20);
            
            fi.e_phentsize = *(uint16_t *)(file_data + 0x2A);
            fi.e_phnum = *(uint16_t *)(file_data + 0x2C);
            fi.e_shentsize = *(uint16_t *)(file_data + 0x2E);
            fi.e_shnum = *(uint16_t *)(file_data + 0x30);
            fi.e_shstrndx = *(uint16_t *)(file_data + 0x32);

        } else if (file_data[4] == 0x02) {
            fi.ei_class = 0x02;
            fi.fi64.e_entry = *(uint64_t *)(file_data + 0x18);
            fi.fi64.e_phoff = *(uint64_t *)(file_data + 0x20);
            fi.fi64.e_shoff = *(uint64_t *)(file_data + 0x28);

            fi.e_phentsize = *(uint16_t *)(file_data + 0x36);
            fi.e_phnum = *(uint16_t *)(file_data + 0x38);
            fi.e_shentsize = *(uint16_t *)(file_data + 0x3A);
            fi.e_shnum = *(uint16_t *)(file_data + 0x3C);
            fi.e_shstrndx = *(uint16_t *)(file_data + 0x3E);

        } else {
            fprintf(stderr, "[!] Ошибка: Неизвестное значение EI_CLASS.\n");
            free(file_data);
            close(fd);
            free(fi.file_dir);
            return;
        }

        // Поиск сегмента под нагрузку и размещение ее в нем
        for (uint16_t ph = 0; ph < fi.e_phnum; ph++ ) {
            // 32 битное приложение
            if (fi.ei_class == 0x01) {
                fi.fi32.e_phoff += fi.e_phentsize;

                // PT_LOAD and PF_X
                if (
                    *(uint32_t *)(file_data + fi.fi32.e_phoff) == 0x01 &&    
                    *(uint32_t *)(file_data + fi.fi32.e_phoff + 0x18) & 0x01
                    ) {
                        uint32_t e_phoff_next = *(uint32_t *)(file_data + fi.fi32.e_phoff + fi.e_phentsize + 0x04);     // RAW смещение следующего сегмента

                        if (e_phoff_next % 0x1000 == 0) {                                                               // Проверка, что RAW смещение след сегмента кратно 0x1000
                            uint32_t p_offset = *(uint32_t *)(file_data + fi.fi32.e_phoff + 0x04);                      // RAW смещение сегмента в файле
                            fi.fi32.offset_free = p_offset + *(uint32_t *)(file_data + fi.fi32.e_phoff + 0x10);         // RAW смещение свободного места в сегменте
                            fi.payload_size = sizeof(payload32);

                            if (fi.fi32.offset_free + fi.payload_size + 0x05 <= e_phoff_next) {                         // Проверка, влезает ли нагрузка или нет
                                memcpy((uint8_t *)(file_data + fi.fi32.offset_free), payload32, sizeof(payload32));     // Копируем нагрузку
                                printf("[+] Нагрузка распологается по RAW смещению 0x%08lx\n", fi.fi32.offset_free);

                                if (!fi.pic){
                                   fi.fi32.file_vaddr = *(uint32_t *)(file_data + fi.fi32.e_phoff + 0x08) -             // Сохраняем адрес загрузки сегмента
                                   *(uint32_t *)(file_data + fi.fi32.e_phoff + 0x04);                                   
                                }

                                add_link_to_payload(file_data, file_size, &fi);                                         // Добавление переходов на нагрузку

                                break;
                            }
                        }
                }
            // 64 битное приложение
            } else {
                fi.fi64.e_phoff += fi.e_phentsize;
                
                // PT_LOAD and PF_X
                if (
                    *(uint32_t *)(file_data + fi.fi64.e_phoff) == 0x01 && \
                    *(uint32_t *)(file_data + fi.fi64.e_phoff + 0x04) & 0x01
                    ) {
                        uint64_t e_phoff_next = *(uint64_t *)(file_data + fi.fi64.e_phoff + fi.e_phentsize + 0x08);     // RAW смещение следующего сегмента

                        if (e_phoff_next % 0x1000 == 0) {                                                               // Проверка, что RAW смещение след сегмента кратно 0x1000
                            uint64_t p_offset = *(uint64_t *)(file_data + fi.fi64.e_phoff + 0x08);                      // RAW смещение сегмента в файле
                            fi.fi64.offset_free = p_offset + *(uint64_t *)(file_data + fi.fi64.e_phoff + 0x20);         // RAW смещение свободного места в сегменте
                            fi.payload_size = sizeof(payload64);

                            if (fi.fi64.offset_free + fi.payload_size + 0x05 <= e_phoff_next) {                         // Проверка, влезает ли нагрузка или нет
                                memcpy((uint8_t *)(file_data + fi.fi64.offset_free), payload64, sizeof(payload64));     // Копируем нагрузку
                                printf("[+] Нагрузка распологается по RAW смещению 0x%08lx\n", fi.fi64.offset_free);

                                if (!fi.pic){
                                   fi.fi64.file_vaddr = *(uint64_t *)(file_data + fi.fi64.e_phoff + 0x10) -             // Сохраняем адрес загрузки сегмента
                                   *(uint64_t *)(file_data + fi.fi64.e_phoff + 0x08);                        
                                }

                                add_link_to_payload(file_data, file_size, &fi);                                         // Добавление переходов на нагрузку

                                break;
                            }
                        }
                }
            }
            
        }
           

    } else {
        fprintf(stderr, "[!] Ошибка: Не удалость вставить нагрузку.\n");
        free(file_data);
        close(fd);
        free(fi.file_dir);
        return;
    }

    free(file_data);            // Освобождаем память
    close(fd);                  // Закрываем файл
    free(fi.file_dir);          // Освобождаем память
}

int main(int argc, char *argv[]) {
    DIR *dir = opendir(".");
    if (!dir) {
        perror("[!] Ошибка: Не удалось открыть текущую директорию.\n");
        return 0;
    }

    int file_count = 0;         // Счетчик корректных файлов
    struct dirent *entry;
    struct stat file_stat;
    while ((entry = readdir(dir)) != NULL) {
        // Пропускаем текущую и родительскую директории
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Проверяем, является ли объект файлом
        if (stat(entry->d_name, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
            char hash_str[EVP_MAX_MD_SIZE * 2 + 1] = {0};
            if (compute_sha256(entry->d_name, hash_str, sizeof(hash_str))) {        // Генерируем хэш файла
                if (is_hash_known(hash_str)) {                                      // Проверяем на наличие хэша в массиве
                    file_count++;  
                    printf("\n%d) ", file_count);

                    patch_file(entry->d_name, &file_stat.st_size);                  // Патчим файл
                }
            }
        }
    }

    if (!file_count) {
        printf("[!] Ошибка: Подходящих файлов не найдено.\n");
    }

    closedir(dir);      // Закрываем каталог
    return 0;
}
