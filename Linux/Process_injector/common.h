#ifndef COMMON_H
#define COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>

struct File_info_32
{
    uint32_t e_phoff;                       // RAW смещение программного заголовка
    uint32_t addr_free;                     // RVA/VA нагрузки
    uint32_t orig_vaddr;                    // VA оригинальной инструкции
    uint32_t dynamic_vaddr;                 // RVA сегмента dynamic
    uint32_t dynamic_memsz;                 // Размер сегмента

};

struct File_info_64
{
    uint64_t e_phoff;
    uint64_t addr_free;
    uint64_t orig_vaddr;
    uint64_t dynamic_vaddr;                 
    uint64_t dynamic_memsz;                 

};

struct Process_info
{   
    pid_t pid;                              // PID
    int mem_fd;                             // Дескриптор файла /proc/[pid]/mem
    unsigned long int process_addr;         // Адрес загрузки
    
    uint8_t ei_class;                       // Разрядность файла
    bool pic;                               // Позиционно независимый код - 1, или нет - 0

    union
    {
        struct File_info_32 fi32;
        struct File_info_64 fi64;
    };
    
    uint16_t e_phentsize;                   // Размер одного программного заголовка
    uint16_t e_phnum;                       // Количество программных заголовков
    
    size_t payload_size;                    // Размер нагрузки
};

// Функции вставки перехода на нагрузку
void p_m_ip(struct Process_info *);
void p_m_cur_inst(struct Process_info *);
void p_m_got_plt(struct Process_info *);
void p_m_fini(struct Process_info *);
void p_m_fini_array(struct Process_info *);
#endif // COMMON_H