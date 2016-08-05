#include "grep_tlv.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "fast_tlv.h"

void GT_GrepTlv_initConf(GT_GrepTlvConf *conf) {
	memset(conf, 0, sizeof(GT_GrepTlvConf));

	/* Default conf. */
	conf->print_raw = false;
	conf->print_path = true;
	conf->print_tlv_hdr = false;
	conf->trunc_tlv_tag = 0;
	conf->print_tlv_hdr_only = false;
}

int  GT_grepTlv(GT_GrepTlvConf *conf, char *pattern, char *prefix, int *map, unsigned char *buf, GT_FTLV *t, unsigned char *raw, size_t *rlen) {
	int res = GT_UNKNOWN_ERROR;
	unsigned tag;
	char *p = pattern;
	int roll = 1;
	int term = 0;
	int match = 0;
	int idx = -1;
	int *idx_map = NULL;

	while (roll) {
		char *mod = NULL;
		tag = strtol(p, &mod, 16);

		if (p == mod) {
			fprintf(stderr, "Invalid pattern: '%s'\n", p);
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}

		if (*mod == '[') {
			idx = strtol(mod + 1, &mod, 10);
			if (*mod != ']') {
				fprintf(stderr, "Invalid index in pattertn: '%s'\n", p);
				res = GT_INVALID_FORMAT;
				goto cleanup;
			}
			mod++;
		}

		switch (*mod) {
			case 0:
				term = 1;
				roll = 0;
				break;
			case ',':
				p = mod + 1;
				break;
			case '.':
				p = mod + 1;
				roll = 0;
				break;
			default:
				fprintf(stderr, "Invalid pattern: '%s'\n", p);
				res = GT_INVALID_FORMAT;
				goto cleanup;
		}

		if (t->tag == tag) {
			match = 1;
			map[tag]++;
		}
	}

	if (match && (idx < 0 || map[t->tag] == idx + 1)) {
		char pre[1024];
		snprintf(pre, sizeof(pre), "%s%s%02x",
				(prefix ? prefix: ""),
				((prefix && *prefix)?".":""),
				t->tag
		);

		if (conf->print_path_index) {
			snprintf(pre + strlen(pre), sizeof(pre) - strlen(pre), "[%d]", map[t->tag] - 1);
		}

		if (term) {
			size_t i;
			unsigned char *ptr = NULL;
			size_t len;
			size_t dat_len = (conf->trunc_tlv_tag == t->tag && conf->trunc_len < t->dat_len) ? conf->trunc_len : t->dat_len;

			if (conf->print_tlv_hdr_only) {
				ptr = buf;
				len = t->hdr_len;
			} else {
				if (conf->print_tlv_hdr) {
					ptr = buf;
					len = dat_len + t->hdr_len;
				} else {
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
				printf("\n");
			}
		} else {
			unsigned char *ptr = buf + t->hdr_len;
			size_t len = t->dat_len;
			GT_FTLV n;

			idx_map = calloc(IDX_MAP_LEN, sizeof(int));
			while (len > 0) {

				res = GT_FTLV_memRead(ptr, len, &n);
				if (res != GT_OK) break;

				res = GT_grepTlv(conf, p, pre, idx_map, ptr, &n, raw, rlen);
				if (res != GT_OK) goto cleanup;

				ptr += n.hdr_len + n.dat_len;
				len -= n.hdr_len + n.dat_len;
			}
		}
	}
	res = GT_OK;
cleanup:
	if (idx_map) free(idx_map);
	return res;
}
