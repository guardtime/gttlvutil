#ifndef DIR_H
#define	DIR_H

typedef struct DIRECTORY_st DIRECTORY;
typedef struct ENTITY_st ENTITY;

enum DIR_STATUS {
	DIR_OK = 0,
	DIR_UNABLE_TO_OPEN,
	DIR_NOT_OPEND,
	DIR_NO_MORE_FILES,
	DIR_NO_FILES_FOUND,
	DIR_OUT_OF_MEMORY,
	DIR_UNKNOWN_ERROR

};

enum FILE_TYPE {
	DIR_DIR,
	DIR_FILE,
	DIR_OTHER,
	DIR_UNKNOWN
};

int DIRECTORY_open(const char *dir_name, DIRECTORY **dir);
void DIRECTORY_close(DIRECTORY *dir);
int DIRECTORY_getNextEntity(DIRECTORY *dir, ENTITY **next);
const char *ENTITY_getName(ENTITY *entity);
int ENTITY_getType(ENTITY *entity);
int DIRECTORY_getMyPath(char *path, size_t path_len, char *arg0);

#endif	/* DIR_H */

