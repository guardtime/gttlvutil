#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tlvdump.h"
#include "desc.h"

void chain_map_free(struct desc_st *map) {
	if (map != NULL) {
		if (map->val != NULL) free(map->val);
		free(map);
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

static int store_nested(struct desc_st *map_in, char *key, char *val) {
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
		res = store_nested(map, ptr + 1, val);
		if (res != KSI_OK) goto cleanup;
	} else {
		map->val = val;
	}

	res = KSI_OK;

cleanup:

	return res;

}

static int store_line(struct desc_st *map_in, char *key, char *val) {
	int res = KSI_UNKNOWN_ERROR;
	long tag;
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

	res = desc_get(map_in, tag, true, &map);
	if (res != KSI_OK) goto cleanup;

	if (*ptr) {
		res = store_nested(map, ptr + 1, val);
		if (res != KSI_OK) goto cleanup;
	} else {
		map->val = val;
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int read_line(FILE *f, struct desc_st *map) {
	int res = KSI_UNKNOWN_ERROR;
	char key[256];
	char val[1024];
	int rd;

	rd = fscanf(f, " %256s %1024[^\n]\n", key, val);
	if (rd == 2) {
		res = store_line(map, key, strdup(val));
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int desc_init(struct desc_st *desc, const char *descFile) {
	int res = KSI_UNKNOWN_ERROR;
	FILE *f = NULL;

	if (descFile == NULL || desc == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}


	desc->val = NULL;
	memset(desc->map, 0, sizeof(desc->map));

	f = fopen(descFile, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to read input file: '%s'.\n", descFile);
		goto cleanup;
	}

	while (!feof(f)) {
		res = read_line(f, desc);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;
	
cleanup:

	if (f != NULL) fclose(f);
	return res;
	
}
