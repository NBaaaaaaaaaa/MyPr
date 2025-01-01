#ifndef COMMON_H
#define COMMON_H
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>  
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

struct File_info_32
{
    uint32_t e_entry;                       // Точка входа 
    uint32_t e_phoff;                       // RAW смещение массива программных заголовков
    uint32_t e_shoff;                       // RAW смещение массива секционных заголовков
    uint32_t offset_free;                   // RAW смещение нагрузки

    uint32_t need_sh_offset;                // RAW смещение необходимой секции
    uint32_t need_sh_addr;                  // RVA секции в памяти (пока программа работает с so). необходимо для патчинга rela.dyn
    uint32_t need_sh_size;                  // Размер секции rel*.dyn

    uint32_t file_vaddr;                    // Адрес загрузки для EXEC файлов
};

struct File_info_64
{
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint64_t offset_free;

    uint64_t need_sh_offset;
    uint64_t need_sh_addr;    
    uint64_t need_sh_size;    

    uint64_t file_vaddr;                       
};

struct File_info
{   
    const char *file_path;                  // Название файла
    char *file_dir;                         // Название директории
    uint8_t ei_class;                       // Разрядность файла
    bool pic;                               // Позиционно независимый код - 1, или нет - 0

    union
    {
        struct File_info_32 fi32;
        struct File_info_64 fi64;
    };
    
    uint16_t e_phentsize;                   // Размер одного программного заголовка
    uint16_t e_phnum;                       // Количество программных заголовков
    uint16_t e_shentsize;                   // Размер одного секционного заголовка
    uint16_t e_shnum;                       // Количество секционных заголовков
    uint16_t e_shstrndx;                    // Индекс секционного заголовка с названиями секций

    size_t payload_size;                    // Размер нагрузки
};

// Фукнции реализации переходна на нагрузку
void fm_e_entry(unsigned char *const, const size_t *const, const struct File_info *const);
void fm_init_fini(unsigned char *const, const size_t *const, struct File_info *const, uint8_t);
void fm_init_fini_array(unsigned char *const, const size_t *const, struct File_info *const, bool);
void fm_plt(unsigned char *const, const size_t *const, struct File_info *const);

#endif // COMMON_H