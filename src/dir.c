#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "dir.h"
#ifdef _WIN32
#include <windows.h>

struct ENTITY_st {
	WIN32_FIND_DATA entity;
};

struct DIRECTORY_st {
	HANDLE findHandle;
	struct ENTITY_st currentEntity;
	int isOpend;
	int isJustopend;
};

#else
#include <dirent.h>
#include <unistd.h>

struct ENTITY_st {
	struct dirent *entity;
};

struct DIRECTORY_st {
	ENTITY next;
	DIR *directory;
};

#endif


static void directory_init(DIRECTORY *dir) {
#ifdef _WIN32
	dir->findHandle = INVALID_HANDLE_VALUE;
	dir->isOpend = 0;
	dir->isJustopend = 0;
#else
	dir->directory = NULL;
	dir->next.entity = NULL;
#endif
}


int DIRECTORY_open(const char *dir_name, DIRECTORY **dir) {
	int res;
	DIRECTORY *tmp = NULL;
#ifdef _WIN32
	size_t dir_name_len = 0;
	HANDLE tmp_handle = NULL;
	DWORD error;
	char path[MAX_PATH];
#endif

	tmp = (DIRECTORY*)malloc(sizeof(DIRECTORY));
	if (tmp == NULL) {
		res = DIR_OUT_OF_MEMORY;
		goto cleanup;
	}

	directory_init(tmp);

#ifdef _WIN32
	dir_name_len = strlen(dir_name);
	if (dir_name[dir_name_len - 1] == '\\'  || dir_name[dir_name_len - 1] == '/')
		GT_snprintf(path, sizeof(path), "%s*", dir_name);
	else
		GT_snprintf(path, sizeof(path), "%s\\*", dir_name);

	tmp_handle = FindFirstFile(path, &tmp->currentEntity.entity);
	if(tmp_handle == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND) {
			res = DIR_NO_FILES_FOUND;
		} else {
			res = DIR_UNABLE_TO_OPEN;
		}
	}

	tmp->isOpend = 1;
	tmp->isJustopend = 1;
	tmp->findHandle = tmp_handle;
	tmp_handle = NULL;

#else
	tmp->directory = (DIR*)opendir(dir_name);
	if (tmp->directory == NULL) {
		res = DIR_UNABLE_TO_OPEN;
		goto cleanup;
	}
#endif


	*dir = tmp;
	tmp = NULL;
	res = DIR_OK;

cleanup:
#ifdef _WIN32
	if (tmp_handle != NULL) FindClose(tmp_handle);
#endif
	DIRECTORY_close(tmp);
	return res;
}

void DIRECTORY_close(DIRECTORY *dir) {
	if (dir == NULL) {
		return;
	}
#ifdef _WIN32
	if (dir->findHandle != NULL) FindClose(dir->findHandle);
#else
	if (dir != NULL && dir->directory != NULL) closedir(dir->directory);
#endif


	free(dir);
}

static const char *path_removeFile(const char *origPath, char *buf, size_t buf_len) {
	char *beginingOfFile = NULL;
	size_t path_len;
	char *ret = NULL;

#ifdef _WIN32
	beginingOfFile = strrchr(origPath, '\\');
	if (beginingOfFile == NULL) {
		beginingOfFile = strrchr(origPath, '/');
	}
#else
	beginingOfFile = strrchr(origPath, '/');
#endif

	if (beginingOfFile ==  NULL) {
		buf[0] = '\0';
		return buf;
	}

	path_len = beginingOfFile - origPath;
	if (path_len + 1 > buf_len) return NULL;

	ret = GT_strncpy(buf, origPath, path_len + 1);

	return  ret;
}

#ifdef _WIN32
static char *directory_getMyFullPath(char *buf, size_t buf_len, char *arg0) {
	TCHAR tmp[MAX_PATH];
	DWORD count;
	count = GetModuleFileName(NULL, tmp, MAX_PATH);
	if (count == 0) return NULL;

	GT_strncpy(buf, tmp, buf_len);

	return buf;
}
#else
static char *directory_getMyFullPath(char *buf, size_t buf_len, char *arg0) {
	char tmp[2048];

	/* A full path is provided. */
	if (*arg0 == '/') {
		strcpy(buf, arg0);
		return buf;
	}

	/* Get path to the working directory. */
	if (getcwd (tmp, sizeof(tmp)) != tmp) {
		return NULL;
	}
	strcpy(buf, tmp);

	/* Check whether application path starts with "./". */
	if (*arg0 == '.' && strstr(arg0, "..") != arg0) {
		/* Copy the executable path starting from '/' */
		strcat(buf, strchr(arg0, '/'));
	} else {
		/* Append '/' to the path if not present. */
		if (buf[strlen(buf)] != '/') {
			strcat(buf, "/");
		}
		/* Append executable path. */
		strcat(buf, arg0);
	}

	return buf;
}
#endif

int DIRECTORY_getMyPath(char *path, size_t path_len, char *arg0) {
	int res = GT_UNKNOWN_ERROR;
	char buf[2048];
	char tmp[2048];

	if (path == NULL || path_len == 0) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (directory_getMyFullPath(buf, sizeof(buf), arg0) == NULL) {
		fprintf(stderr, "Unable to retrieve gttlvdump full path.\n");
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	if (path_removeFile(buf, tmp, sizeof(tmp)) == NULL) {
		fprintf(stderr, "Unable to remove file name from path '%s'.\n", buf);
		res = GT_INVALID_FORMAT;
	}

	GT_strncpy(path, tmp, path_len);
	path[path_len - 1] = '\0';
	res = GT_OK;

cleanup:

return res;
}

int DIRECTORY_getNextEntity(DIRECTORY *dir, ENTITY **next) {
	if(dir == NULL || next == NULL);

#ifdef _WIN32
	if (dir->isOpend == 0 || dir->findHandle == NULL || dir->findHandle == INVALID_HANDLE_VALUE) {
		return DIR_NOT_OPEND;
	}

	if (dir->isJustopend) {
		dir->isJustopend = 0;
	} else {
		if (FindNextFile(dir->findHandle, &dir->currentEntity.entity) == 0) {
			DWORD error;
			error = GetLastError();
			if (error == ERROR_NO_MORE_FILES) {
				return DIR_NO_MORE_FILES;
			} else {
				return DIR_UNKNOWN_ERROR;
			}

		}
	}

	*next = &dir->currentEntity;
#else
	struct dirent *entity = NULL;
	entity = readdir(dir->directory);

	if (entity == NULL) {
		return DIR_NO_MORE_FILES;
	} else {
		dir->next.entity = entity;
		*next = &dir->next;
	}
#endif


	return DIR_OK;
}

const char *ENTITY_getName(ENTITY *entity) {
	if (entity == NULL) {
		return NULL;
	}

#ifdef _WIN32
	return entity->entity.cFileName;
#else
	return entity->entity->d_name;
#endif

}

int ENTITY_getType(ENTITY *entity) {
	if (entity == NULL) return DIR_UNKNOWN;

#ifdef _WIN32
	{
	DWORD atr = entity->entity.dwFileAttributes;
	if (atr & FILE_ATTRIBUTE_DIRECTORY) return DIR_DIR;
	else if (atr & FILE_ATTRIBUTE_NORMAL) return DIR_FILE;
	else return DIR_OTHER;
	}
#else
	if (entity->entity->d_type == DT_REG) return DIR_FILE;
	else if (entity->entity->d_type == DT_DIR) return DIR_DIR;
	else return DIR_OTHER;
#endif
}


