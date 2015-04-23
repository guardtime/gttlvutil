#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "tlvdump.h"
#include "fast_tlv.h"
#include "desc.h"

#define INDENT_LEN 4

struct conf_st {
	const char *file_name;
	size_t hdr_len;
	size_t max_depth;
	bool print_off;
	bool wrap;
	bool print_len;
	bool convert;
	bool use_desc;
	struct desc_st desc;
};

const char *descFile = DATA_DIR "ksi.desc";

static print_raw_data(unsigned char *buf, size_t len, size_t prefix_len, struct conf_st *conf) {
	size_t i;

	for (i = 0; i < len; i++) {
		if (conf->wrap &&  i > 0 && i % 64 == 0 ) {
			printf("\n%*s", prefix_len, "");
		}
		printf("%02x", buf[i]);
	}

	if (conf->convert && len <= 8) {
		size_t val = 0;
		for (i = 0; i < len; i++) {
			val = (val << 8) | buf[i];
		}
		printf(" (dec = %llu)", (unsigned long long)val); 
	}
	putchar('\n');
}

static void printTlv(unsigned char *buf, size_t buf_len, KSI_FTLV *t, int level, struct conf_st *conf, struct desc_st *desc) {
	int res;
	unsigned char *ptr = buf + t->hdr_len;
	size_t len = t->dat_len;
	size_t prefix_len = 0;
	struct desc_st *sub = NULL;

	if (conf->use_desc) {
		if (desc == NULL) {
			desc_find(&conf->desc, t->tag, &desc);
		}

		if (desc != NULL && desc->val != NULL) {
			printf("%*s# %s\n", level * INDENT_LEN, "", desc->val);
		}
	}

	if (conf->print_off) {
		prefix_len += printf("%4llu:", (unsigned long long)t->off);
	}

	prefix_len += printf("%*sTLV[0x%02x%s%s]: ", level * INDENT_LEN, "", t->tag, (t->is_fwd ? ",F" : ""), (t->is_nc ? ",N" : ""));
	if (conf->print_len) {
		prefix_len += printf("(len = %llu) ", (unsigned long long)t->dat_len);
	}

	/* Just check if it is a nested TLV. */
	res = KSI_FTLV_memReadN(ptr, len, NULL, 0, NULL);

	if (res != KSI_OK || (conf->max_depth && level + 1 >= conf->max_depth)) {
		print_raw_data(ptr, len, prefix_len, conf);
	} else {
		size_t off = t->off + t->hdr_len;
		KSI_FTLV n;

		putchar('\n');
		while (len > 0) {
			size_t consumed;
			KSI_FTLV_memRead(ptr, len, &n);
			n.off = off;

			desc_find(desc, n.tag, &sub);

			consumed = n.hdr_len + n.dat_len;

			printTlv(ptr, consumed, &n, level + 1, conf, sub);

			off += consumed;

			ptr += consumed;
			len -= consumed;
		}
	}
}

static int read_from(FILE *f, struct conf_st *conf) {
	int res;
	char *header = NULL;
	KSI_FTLV t;
	unsigned char buf[0xffff + 4];
	size_t len;
	size_t off = 0;

	if (conf->hdr_len > 0) {
		header = calloc(conf->hdr_len, 1);
		if (header == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}
		if (fread(header, conf->hdr_len, 1, f) != 1) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}

		for (len = 0; len < conf->hdr_len; len++) {
			printf("%02x", header[len]);
		}
		printf("\n");
	}

	while (1) {
		res = KSI_FTLV_fileRead(f, buf, sizeof(buf), &len, &t);
		if (res != KSI_OK) {
			if (len == 0) break;
			fprintf(stderr, "%s: Failed to parse %llu bytes\n", conf->file_name, (unsigned long long) len);
			break;
		}

		t.off = off;

		printTlv(buf, len, &t, 0, conf, NULL);
		off += len;
	}

	res = KSI_OK;

cleanup:

	if (header != NULL) free(header);

	return res;
}

int main(int argc, char **argv) {
	int res;
	int c;
	FILE *input = NULL;
	size_t i;
	struct conf_st conf;

	memset(&conf, 0, sizeof(conf));

	while ((c = getopt(argc, argv, "hH:d:xwyza")) != -1) {
		switch(c) {
			case 'H':
				conf.hdr_len = atoi(optarg);
				break;
			case 'h':
				printf("Usage:\n"
						"  gttlvdump [-h] [-H number] tlvfile\n"
						"    -h       This help message\n"
						"    -H num   Constant header lenght.\n"
						"    -d num   Max depth of nested elements\n"
						"    -x       Display file offset for every TLV\n"
						"    -w       Wrap the output.\n"
						"    -y       Show content length.\n"
						"    -z       Convert payload with length les than 8 bytes to decimal.\n"
						"    -a       Annotate known KSI elements.\n"
				);
				res = KSI_OK;
				goto cleanup;
			case 'd':
				conf.max_depth = atoi(optarg);
				break;
			case 'x':
				conf.print_off = true;
				break;
			case 'w':
				conf.wrap = true;
				break;
			case 'y':
				conf.print_len = true;
				break;
			case 'z':
				conf.convert = true;
				break;
			case 'a':
				res = desc_init(&conf.desc, DATA_DIR "ksi.desc");
				if (res != KSI_OK) {
					fprintf(stderr, "Unable to parse description file '%s' (error = %d) -  option ignored.\n", optarg, res);
				} else {
					conf.use_desc = true;
				}
				break;
			default:
				fprintf(stderr, "Unknown parameter, try -h.");
				goto cleanup;
		}
	}

	if (optind >= argc) {
		res = read_from(stdin, &conf);
		if (res != KSI_OK) goto cleanup;
	} else {
		size_t i;
		for (i = 0; optind + i < argc; i++) {
			conf.file_name = argv[optind + i];

			input = fopen(conf.file_name, "rb");
			if (input == NULL) {
				fprintf(stderr, "%s: Unable to open file.\n", argv[optind + i]);
				continue;
			}

			res = read_from(input, &conf);
			fclose(input);
			input = NULL;
			if (res != KSI_OK) goto cleanup;
		}
	}

cleanup:

	if (input != NULL) fclose(input);
	if (conf.use_desc) desc_cleanup(&conf.desc);


	return 0;
}
