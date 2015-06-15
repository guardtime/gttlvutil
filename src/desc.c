#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tlvdump.h"
#include "desc.h"

void desc_cleanup(struct desc_st *desc) {
	if (desc != NULL) {
		size_t i;
		if (desc->val != NULL) free(desc->val);
		for (i = 0; i < sizeof(desc->map) / sizeof(struct desc_st *); i++) {
			if (desc->map[i] != NULL) {
				desc_cleanup(desc->map[i]);
				free(desc->map[i]);
				desc->map[i] = NULL;
			}
		}
	}
}

static int desc_get(struct desc_st *in, unsigned tag, bool create, struct desc_st **out) {
	int res = KSI_UNKNOWN_ERROR;

	struct desc_st *ptr = NULL;
	size_t pos;

	size_t i;
	size_t arr_len;

	/* If in is NULL, do not shout at the caller, this probably means
     * the last query failed. */
	if (in == NULL) {
		*out = NULL;
		res = KSI_OK;
		goto cleanup;
	}

	/* The output parameter shouldn't be NULL in any case. */
	if (out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	arr_len = sizeof(in->map) / sizeof(struct desc_st *);

	/* Find a spot or the correct container. */
	for (i = 0; i < arr_len; i++) {
		pos = ( + i) % arr_len;
		if (in->map[pos] == NULL || in->map[pos]->key == tag) {
			break;
		}
	}

	if (in->map[pos] != NULL && in->map[pos]->key != tag) {
		res = KSI_BUFFER_OVERFLOW;
		goto cleanup;
	}

	/* If it was uninitialized, initialize. */
	if (in->map[pos] == NULL && create) {
		if (in->map[pos] != NULL) {
			res = KSI_BUFFER_OVERFLOW;
			goto cleanup;
		}

		ptr = calloc(sizeof(struct desc_st), 1);
		if (ptr == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}

		ptr->key = tag;

		in->map[pos] = ptr;
		ptr = NULL;
	}

	*out = in->map[pos];

	res = KSI_OK;

cleanup:
	
	if (ptr != NULL) free(ptr);

	return res;
}

int desc_find(struct desc_st *in, unsigned tag, struct desc_st **out) {
	return desc_get(in, tag, false, out);
}	

static int store_nested(struct desc_st *map_in, char *key, int type, char *val) {
	int res = KSI_UNKNOWN_ERROR;
	long tag;
	char *ptr;
	struct desc_st *map = NULL;

	/* Validate input. */
	if (key == NULL || *key == '\0' || val == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Convert string to long. */
	tag = strtol(key, &ptr, 16);

	/* Validate tag value and reminder. */
	if (key == ptr || tag < 0 || tag > ((KSI_TLV_MASK_TLV8_TYPE << 8) | 0xff) || (*ptr && *ptr != '.')) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	/* Find or create the container for this tag. */
	res = desc_get(map_in, tag, true, &map);
	if (res != KSI_OK) goto cleanup;

	/* If the key is longer, recurse. */
	if (*ptr) {
		res = store_nested(map, ptr + 1, type, val);
		if (res != KSI_OK) goto cleanup;
	} else {
		map->val = val;
		map->type = type;
	}

	res = KSI_OK;

cleanup:

	return res;

}

/**
 * Convert textual string into enum values or -1 if unknown.
 */
static int get_type(char *ts) {
	if (!strcmp("*", ts)) return TLV_COMPOSITE;
	if (!strcmp("INT", ts)) return TLV_INT;
	if (!strcmp("RAW", ts)) return TLV_RAW;
	if (!strcmp("STR", ts)) return TLV_STR;
	if (!strcmp("TIME", ts)) return TLV_TIME;
	if (!strcmp("IMPRINT", ts)) return TLV_IMPRINT;
	
	return -1;
}

static int store_line(struct desc_st *map_in, char *key, char *ts, char *val) {
	int res = KSI_UNKNOWN_ERROR;
	long tag;
	int type;
	char *ptr;
	struct desc_st *map = NULL;	

	if (map_in == NULL || key == NULL || *key == '\0' || val == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tag = strtol(key, &ptr, 16);
	if (key == ptr || tag < 0 || tag > ((KSI_TLV_MASK_TLV8_TYPE << 8) | 0xff) || (*ptr && *ptr != '.')) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	/* Convert the type into a number .*/
	type = get_type(ts);
	if (type < 0) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	res = desc_get(map_in, tag, true, &map);
	if (res != KSI_OK) goto cleanup;

	if (*ptr) {
		res = store_nested(map, ptr + 1, type, val);
		if (res != KSI_OK) goto cleanup;
	} else {
		map->val = val;
		map->type = type;
	}

	res = KSI_OK;

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

static int read_line(FILE *f, struct desc_st *map) {
	int res = KSI_UNKNOWN_ERROR;
	char key[256];
	char type[16];
	char val[1024];
	char line[2048];
	size_t len;
	int rd;

	/* Read the whole line and drop any character that does not fit the buffer. */
	len = consume_line(f, line, sizeof(line));

	if (!ignore_line(line)) {
		trim_line(line, len);

		rd = sscanf(line, " %256s %16s %1024[^\n]\n", key, type, val);
		if (rd == 3) {
			res = store_line(map, key, type, strdup(val));
			if (res != KSI_OK) goto cleanup;
		}
	}
	res = KSI_OK;

cleanup:

	return res;
}

int desc_add_file(struct desc_st *desc, const char *descFile) {
	int res = KSI_UNKNOWN_ERROR;
	FILE *f = NULL;
	size_t ln = 0;

	if (descFile == NULL || desc == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	f = fopen(descFile, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to read input file: '%s'.\n", descFile);
		goto cleanup;
	}

	while (!feof(f)) {
		++ln;
		res = read_line(f, desc);
		if (res != KSI_OK) {
			if (res == KSI_INVALID_FORMAT) {
				fprintf(stderr, "%s:%u - invalid format\n", descFile, ln);
			} else {
				goto cleanup;
			}
		}
	}

	res = KSI_OK;
	
cleanup:

	if (f != NULL) fclose(f);
	return res;
	
}
