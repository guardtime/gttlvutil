#include "grep_tlv.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "fast_tlv.h"

struct pattern_st {
	bool match_tag;
	int tag;
	bool match_index;
	int index;

	struct pattern_st *match;
	struct pattern_st *no_match;
};

void GT_GrepPattern_free(struct pattern_st *p) {
	if (p != NULL) {
		struct pattern_st *tmp = NULL;
		GT_GrepPattern_free(p->match);
		tmp = p->no_match;
		while (tmp != NULL) {
			struct pattern_st *next = tmp->no_match;
			/* Freed already above. */
			tmp->match = NULL;
			free(tmp);
			tmp = next;
		}
		free(p);
	}
}

enum {
	MODE_NEXT,
	MODE_BEGIN,
	MODE_TAG,
	MODE_INDEX,
	MODE_ERROR
};

/* This function will copy the 'mach' pointer from the last element of the 'no_mach' chain to all of
 * the elements in the 'no_mach' chain. */
struct pattern_st *update_match(struct pattern_st *p) {
	if (p == NULL) {
		return NULL;
	}

	/* If this element has 'no_mach' set, use the 'mach' value from the next/last one. */
	if (p->no_match != NULL) {
		p->match = update_match(p->no_match);
	}

	/* If the 'mach' value is set update the next level. */
	if (p->match != NULL) {
		p->match->match = update_match(p->match);
	}

	return p->match;
}

int GT_GrepPattern_parse(const char *in, struct pattern_st **out) {
	int res = GT_UNKNOWN_ERROR;
	struct pattern_st *tmp = NULL;
	struct pattern_st *ptr = NULL;
	const char *p = in;
	int mode = MODE_BEGIN;
	bool any_tag = false;

	if (in == NULL || out == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (*in == '\0') {
		fprintf(stderr, "Invalid pattern: the pattern must not be empty.\n");
		res = GT_INVALID_CMD_PARAM;
		goto cleanup;
	}

	tmp = calloc(sizeof(struct pattern_st), 1);
	if (tmp == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	ptr = tmp;
	while (*p != '\0') {
		switch(mode) {
			case MODE_NEXT:
				if (*p == '.') {
					ptr->match = calloc(sizeof(struct pattern_st), 1);
					if (ptr->match == NULL) {
						res = GT_OUT_OF_MEMORY;
						goto cleanup;
					}
					ptr = ptr->match;
					p++;
					any_tag = false;
					continue;
				}

				if (*p == ',') {
					ptr->no_match = calloc(sizeof(struct pattern_st), 1);
					if (ptr->no_match == NULL) {
						res = GT_OUT_OF_MEMORY;
						goto cleanup;
					}
					ptr = ptr->no_match;
					p++;
					any_tag = false;
					continue;
				}
				/* Fall to MODE_BEGIN. */
			case MODE_BEGIN:
				if (*p == '*' && !any_tag && !ptr->match_tag) {
					ptr->match_tag = false;
					p++;
					mode = MODE_NEXT;
					any_tag = true;
					continue;
				} else if (IS_HEX(*p) && !any_tag) {
					ptr->match_tag = true;
					mode = MODE_TAG;
					any_tag = false;
					continue;
				}

				if (*p == '[') {
					ptr->match_index = true;
					mode = MODE_INDEX;
					p++;
					continue;
				}

				/* This must be an error. */
				mode = MODE_ERROR;
				break;
			case MODE_TAG:
				if (IS_HEX(*p)) {
					ptr->tag = (ptr->tag << 4) + HEXCHAR_TO_DEC(*p);
					p++;
					continue;
				}

				/* On unexpected input default to MODE_NEXT. */
				mode = MODE_NEXT;
				break;
			case MODE_INDEX:
				if (IS_DIGIT(*p)) {
					ptr->index = ptr->index * 10 + DECCHAR_TO_DEC(*p);
					p++;
					continue;
				}

				if (*p == ']') {
					mode = MODE_NEXT;
					p++;
					continue;
				}

				/* This is an error condition. */
				mode = MODE_ERROR;
				break;

			case MODE_ERROR:
				fprintf(stderr, "Invalid pattern '%s': unexpected character '%c'\n", in, *p);
				res = GT_INVALID_CMD_PARAM;
				goto cleanup;
		}
	}

	/* The 'match' pointer is evaluated only for the last element in the 'no_mach' chain. Update the 'match'
	 * pointers for all the elements in the 'no_mach' chain. */
	tmp->match = update_match(tmp);

	*out = tmp;
	tmp = NULL;

	res = GT_OK;

cleanup:

	GT_GrepPattern_free(tmp);

	return res;
}


void GT_GrepTlv_initConf(GT_GrepTlvConf *conf) {
	memset(conf, 0, sizeof(GT_GrepTlvConf));

	/* Default conf. */
	conf->print_raw = false;
	conf->print_path = false;
	conf->print_tlv_hdr = false;
	conf->trunc_tlv_tag = 0;
	conf->print_tlv_hdr_only = false;
	conf->pattern = NULL;
	conf->in_enc = GT_BASE_2;
}

int GT_grepTlv(GT_GrepTlvConf *conf, struct pattern_st *pattern, char *prefix, GT_ElementCounter *map, unsigned char *buf, GT_FTLV *t, unsigned char *raw, size_t *rlen) {
	int res = GT_UNKNOWN_ERROR;
	struct pattern_st *pt = pattern;
	char pre[1024];
	GT_ElementCounter *idx_map = NULL;

	/* Count the instance of this particular tag. */
	map->element_count[t->tag]++;
	map->count++;

	while (pt != NULL) {
		/* Tag value matches. */
		if (pt->match_tag && pt->tag != t->tag) {
			pt = pt->no_match;
			continue;
		}

		/* Index of the element matches. */
		if (pt->match_index && (
				( pt->match_tag && pt->index + 1 != map->element_count[t->tag]) ||
				(!pt->match_tag && pt->index + 1 != map->count))) {
			pt = pt->no_match;
			continue;
		}

		/* Create the prefix string. */
		GT_snprintf(pre, sizeof(pre), "%s%s%02x",
				(prefix ? prefix : ""),
				((prefix && *prefix) ? "." : ""),
				t->tag
		);

		/* Add the index value, if requested. */
		if (conf->print_path_index) {
			GT_snprintf(pre + strlen(pre), sizeof(pre) - strlen(pre), "[%llu]", (unsigned long long) map->element_count[t->tag] - 1);
		}

		if (pt->match == NULL) {
			/* The matching pattern has been found. */
			size_t i;
			unsigned char *ptr = NULL;
			size_t len;
			size_t dat_len = (conf->trunc_tlv_tag == t->tag && conf->trunc_len < t->dat_len) ? conf->trunc_len : t->dat_len;

			if (conf->print_tlv_hdr_only) {
				/* Set the pointer to the header. */
				ptr = buf;
				len = t->hdr_len;
			} else {
				if (conf->print_tlv_hdr) {
					/* Set the pointer to the header. */
					ptr = buf;
					len = dat_len + t->hdr_len;
				} else {
					/* Set the pointer to the data. */
					ptr = buf + t->hdr_len;
					len = dat_len;
				}
			}

			if (conf->print_path && !conf->print_raw) {
				printf("%s: ", pre);
			}

			for (i = 0; i < len; i++) {
				if (conf->print_raw) {
					if (raw != NULL) {
						raw[(*rlen)++] = ptr[i];
					} else {
						putc(ptr[i], stdout);
					}
				} else {
					printf("%02x", ptr[i]);
				}
			}

			if (!conf->print_raw) {
				putc('\n', stdout);
			}
		} else {
			/* Continue the search within nesting TLVs. */
			unsigned char *ptr = buf + t->hdr_len;
			size_t len = t->dat_len;
			GT_FTLV n;

			idx_map = calloc(sizeof(GT_ElementCounter), 1);
			if (idx_map == NULL) {
				res = GT_OUT_OF_MEMORY;
				goto cleanup;
			}

			while (len > 0) {
				res = GT_FTLV_memRead(ptr, len, &n);
				if (res != GT_OK || len < n.hdr_len + n.dat_len) break;

				res = GT_grepTlv(conf, pt->match, pre, idx_map, ptr, &n, raw, rlen);
				if (res != GT_OK) goto cleanup;

				ptr += n.hdr_len + n.dat_len;
				len -= n.hdr_len + n.dat_len;
			}

			free(idx_map);
			idx_map = NULL;
		}

		/* Continue search as there might be wildcards. */
		pt = pt->no_match;
	}

	res = GT_OK;

cleanup:

	if (idx_map != NULL) free(idx_map);

	return res;
}

