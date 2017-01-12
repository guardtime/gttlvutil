#include "desc.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#	define strdup(s) _strdup(s)
#endif

void desc_cleanup(struct desc_st *desc) {
	if (desc != NULL) {
		size_t i;
		if (desc->val != NULL) {
			free(desc->val);
			desc->val = NULL;
		}
		desc->key = 0;
		desc->type = 0;
		for (i = 0; i < sizeof(desc->map) / sizeof(struct desc_st *); i++) {
			if (desc->map[i] != NULL) {
				desc_cleanup(desc->map[i]);
				free(desc->map[i]);
				desc->map[i] = NULL;
			}
		}
		for (i = 0; i < desc->magics_len; i++) {
			free(desc->magics[i].desc);
		}
		free(desc->magics);
	}
}

static int desc_get(struct desc_st *in, unsigned tag, bool create, struct desc_st **out, bool *created) {
	int res = GT_UNKNOWN_ERROR;

	struct desc_st *ptr = NULL;
	size_t pos;
	size_t arr_len;

	/* If in is NULL, do not shout at the caller, this probably means
	 * the last query failed. */
	if (in == NULL) {
		*out = NULL;
		res = GT_OK;
		goto cleanup;
	}

	/* The output parameter shouldn't be NULL in any case. */
	if (out == NULL || (create == true && created == NULL)) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Find a spot or the correct container. */
	arr_len = sizeof(in->map) / sizeof(struct desc_st *);
	for (pos = 0; pos < arr_len; pos++) {
		if (in->map[pos] == NULL || in->map[pos]->key == tag) {
			break;
		}
	}

	if (pos >= arr_len || (in->map[pos] != NULL && in->map[pos]->key != tag)) {
		res = GT_BUFFER_OVERFLOW;
		goto cleanup;
	}

	/* If it was uninitialized, initialize. */
	if (in->map[pos] == NULL && create) {
		ptr = calloc(sizeof(struct desc_st), 1);
		if (ptr == NULL) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}
		*created = true;

		ptr->key = tag;

		in->map[pos] = ptr;
		ptr = NULL;
	}

	*out = in->map[pos];

	res = GT_OK;

cleanup:

	if (ptr != NULL) free(ptr);

	return res;
}

int desc_find(struct desc_st *in, unsigned tag, struct desc_st **out) {
	return desc_get(in, tag, false, out, NULL);
}

static int store_nested(struct desc_st *map_in, const char *key, int type, const char *val, bool override) {
	int res = GT_UNKNOWN_ERROR;
	long tag;
	char *ptr;
	struct desc_st *map = NULL;
	bool isNew = false;

	/* Validate input. */
	if (key == NULL || *key == '\0' || val == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Convert string to long. */
	tag = strtol(key, &ptr, 16);

	/* Validate tag value and reminder. */
	if (key == ptr || tag < 0 || tag > ((GT_TLV_MASK_TLV8_TYPE << 8) | 0xff) || (*ptr && *ptr != '.')) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	/* Find or create the container for this tag. */
	res = desc_get(map_in, tag, true, &map, &isNew);
	if (res != GT_OK) goto cleanup;

	/* If the key is longer, recurse. */
	if (*ptr) {
		res = store_nested(map, ptr + 1, type, val, override);
		if (res != GT_OK) goto cleanup;
	} else {
		/* Check if tag was already in map. */
		if (!isNew) {
			/* Throw duplicate error if override flag is not set. */
			if (!override) {
				res = GT_DUPLICATE_ERROR;
				goto cleanup;
			}
			/* Reset the map for given tag. */
			desc_cleanup(map);
			res = desc_get(map_in, tag, true, &map, &isNew);
			if (res != GT_OK) goto cleanup;
		}
		map->val = strdup(val);
		map->type = type;
	}

	res = GT_OK;

cleanup:

	return res;

}

/**
 * Convert textual string into enum values or -1 if unknown.
 */
static int get_type(const char *ts) {
	if (!strcmp("*", ts)) return TLV_COMPOSITE;
	if (!strcmp("INT", ts)) return TLV_INT;
	if (!strcmp("RAW", ts)) return TLV_RAW;
	if (!strcmp("STR", ts)) return TLV_STR;
	if (!strcmp("TIME", ts)) return TLV_TIME;
	if (!strcmp("MTIME", ts)) return TLV_MTIME;
	if (!strcmp("UTIME", ts)) return TLV_UTIME;
	if (!strcmp("IMPRINT", ts)) return TLV_IMPRINT;
	if (!strcmp("@MAGIC", ts)) return TLV_FILE_MAGIC;
	return -1;
}

static int store_magic(struct desc_st *map_in, const char *key, const char *desc) {
	int res = GT_UNKNOWN_ERROR;
	struct file_magic_st *magic;
	size_t i;
	char octet;

	if (map_in == NULL || key == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;	
	}

	if (map_in->magics == NULL) {
		map_in->magics_size = 10;
		map_in->magics = malloc(sizeof(struct file_magic_st) * map_in->magics_size);
	} else if (map_in->magics_size <= map_in->magics_len) {
		map_in->magics_size += 10;
		map_in->magics = realloc(map_in->magics, sizeof(struct file_magic_st) * map_in->magics_size);
	}

	if (map_in->magics == NULL) {
		fprintf(stderr, "Out of memory.\n");
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	magic = map_in->magics + map_in->magics_len++;

	memset(magic, 0, sizeof(struct file_magic_st));
	magic->desc = strdup(desc); 

	/* Assume the key is represented as hex. */
	octet = 0;
	for (i = 0; key[i] != '\0'; i++) {
		char c = tolower(key[i]);

		/* Sanity check. */
		if (magic->len >= sizeof(magic->val)) {
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}

		if (isdigit(c)) {
			octet = (octet << 4) + (c - '0');
		} else if (c >= 'a' && c <= 'f') {
			octet = (octet << 4) + (c - 'a') + 10;
		} else {
			fprintf(stderr, "Unexpected character '%c' (%d) while processing magic header value.\n", c, c);
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}

		/* Store the value for every second input. */
		if ((i + 1) % 2 == 0) {
			magic->val[magic->len++] = octet;
			octet = 0;
		}
	}

	/* Make sure there was no partial octet in the end. */
	if ((i + 1) %2 == 0) {
		/* The last octet was only one character. We assume, the trailing zero was omitted. */
		magic->val[magic->len++] = octet << 4;
	}

	res = GT_OK;

cleanup:

	return res;
}

static int store_tag(struct desc_st *map_in, const char *key, int type, char *val, bool override) {
	int res = GT_UNKNOWN_ERROR;
	long tag;
	char *ptr;
	struct desc_st *map = NULL;
	bool isNew = false;

	if (map_in == NULL || key == NULL || *key == '\0' || val == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tag = strtol(key, &ptr, 16);
	if (key == ptr || tag < 0 || tag > ((GT_TLV_MASK_TLV8_TYPE << 8) | 0xff) || (*ptr && *ptr != '.')) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	res = desc_get(map_in, tag, true, &map, &isNew);
	if (res != GT_OK) goto cleanup;

	if (*ptr) {
		res = store_nested(map, ptr + 1, type, val, override);
		if (res != GT_OK) goto cleanup;
	} else {
		/* Check if tag was already in map. */
		if (!isNew) {
			/* Throw duplicate error if override flag is not set. */
			if (!override) {
				res = GT_DUPLICATE_ERROR;
				goto cleanup;
			}
			/* Reset the map for given tag. */
			desc_cleanup(map);
			res = desc_get(map_in, tag, true, &map, &isNew);
			if (res != GT_OK) goto cleanup;
		}
		map->val = strdup(val);
		map->type = type;
	}

	res = GT_OK;

cleanup:

	return res;
}

static int store_line(struct desc_st *map_in, const char *key, const char *ts, char *val, bool override) {
	int res = GT_UNKNOWN_ERROR;
	int type;

	if (map_in == NULL || key == NULL || *key == '\0' || ts == NULL || val == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Convert the type into a number .*/
	type = get_type(ts);
	if (type < 0) {
		fprintf(stderr, "Unexpected type: '%s'\n", ts);
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	if (type == TLV_FILE_MAGIC) {
		res = store_magic(map_in, key, val);
	} else {
		res = store_tag(map_in, key, type, val, override);
	}

cleanup:

	return res;
}

static size_t consume_line(FILE *f, char *dest, size_t size) {
	size_t len = 0;
	int c;
	while ((c = fgetc(f)) != EOF && c != '\n') {
		if (len + 1 < size) {
			dest[len++] = c;
		}
	}
	dest[len] = '\0';

	return len;
}

static int ignore_line(char *line) {
	/* Ignore whitespace. */
	while (*line != '\0' && isspace(*line)) ++line;

	/* Ignore empty and comment lines. */
	return (*line == '\0' || *line == '#');
}

static size_t trim_line(char *line, size_t len) {
	while (len--> 0 && (isspace(line[len]) || line[len] == '\n' || line[len] == '\r')) {
		line[len] = '\0';
	}
	return len;
}

static int read_line(FILE *f, struct desc_st *map, bool override) {
	int res = GT_UNKNOWN_ERROR;
	char key[256];
	char type[16];
	char val[1024];
	char line[2048];
	int rd;

	/* Read the whole line and drop any character that does not fit the buffer. */
	consume_line(f, line, sizeof(line));

	if (!ignore_line(line)) {
		rd = sscanf(line, " %256s %16s %1024[^\n]\n", key, type, val);
		if (rd == 3) {
			trim_line(val, strlen(val));

			res = store_line(map, key, type, val, override);
			if (res != GT_OK) goto cleanup;
		}
	}
	res = GT_OK;

cleanup:

	return res;
}

int desc_add_file(struct desc_st *desc, const char *descFile, bool override) {
	int res = GT_UNKNOWN_ERROR;
	FILE *f = NULL;
	size_t ln = 0;

	if (descFile == NULL || desc == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	f = fopen(descFile, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to read input file: '%s'.\n", descFile);
		goto cleanup;
	}

	while (!feof(f)) {
		++ln;
		res = read_line(f, desc, override);
		if (res != GT_OK) {
			if (res == GT_INVALID_FORMAT) {
				fprintf(stderr, "%s:%llu - invalid format.\n", descFile, (unsigned long long)ln);
			} else if (res == GT_DUPLICATE_ERROR) {
				fprintf(stderr, "%s:%llu - duplicate description.\n", descFile, (unsigned long long)ln);
				goto cleanup;
			}
		}
	}

	res = GT_OK;

cleanup:

	if (f != NULL) fclose(f);
	return res;

}

