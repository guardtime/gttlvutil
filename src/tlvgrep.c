#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "fast_tlv.h"

#define IDX_MAP_LEN 0x1ffff

struct conf_st {
	const char *file_name;
	char *pattern;
	size_t magic_len;
	bool print_tlv_hdr;
	bool print_raw;
	bool print_path;
	bool print_path_index;
};

void grepTlv(struct conf_st *conf, char *pattern, char *prefix, int *map, unsigned char *buf, GT_FTLV *t) {
	int res;
	unsigned tag;
	char *p = pattern;
	int roll = 1;
	int term = 0;
	int match = 0;
	int idx = -1;

	while (roll) {
		char *mod = NULL;
		tag = strtol(p, &mod, 16);

		if (p == mod) {
			fprintf(stderr, "Invalid pattern: '%s'\n", p);
			exit(1);
		}

		if (*mod == '[') {
			idx = strtol(mod + 1, &mod, 10);
			if (*mod != ']') {
				fprintf(stderr, "Invalid index in pattertn: '%s'\n", p);
				exit(1);
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
				exit(1);
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

			if (conf->print_tlv_hdr) {
				ptr = buf;
				len = t->dat_len + t->hdr_len;
			} else {
				ptr = buf + t->hdr_len;
				len = t->dat_len;
			}

			if (conf->print_path && !conf->print_raw) {
				printf("%s: ", pre);
			}

			for (i = 0; i < len; i++) {
				if (conf->print_raw) {
					putc(ptr[i], stdout);
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
			int i[IDX_MAP_LEN];
			memset(i, 0, sizeof(i));

			while (len > 0) {

				res = GT_FTLV_memRead(ptr, len, &n);
				if (res != GT_OK) break;

				grepTlv(conf, p, pre, i, ptr, &n);

				ptr += n.hdr_len + n.dat_len;
				len -= n.hdr_len + n.dat_len;
			}
		}
	}



}

void grepFile(struct conf_st *conf, FILE *f) {
	int res;
	GT_FTLV t;
	size_t len;
	unsigned char buf[0xffff + 4];
	int idx[IDX_MAP_LEN];

	memset(idx, 0, sizeof(idx));

	while (!feof(f)) {
		res = GT_FTLV_fileRead(f, buf, sizeof(buf), &len, &t);
		if (len == 0) break;

		if (res != GT_OK) {
			fprintf(stderr, "%s: Failed to parse TLV.\n", conf->file_name);
			exit(1);
		}

		grepTlv(conf, conf->pattern, NULL, idx, buf, &t);
	}
}


void printHelp(FILE *f) {
	fprintf(f, "Usage:\n\n"
			"  gttlvgrep <options> [pattern] <[tlv file]>\n\n"
			"Pattern:\n"
			"  The pattern describes the hirarchy of the element or elements\n"
			"  that the user is looking for. The path describes the TLV values\n"
			"  in layers of the TLV tree, starting from the outermost. Each level\n"
			"  is sepparated by a dot '.'. Each layer may contain one or multiple\n"
			"  TLV tag value(s). Multiple values are sepparater by a comma ','.\n"
			"  Each TLV tag may be followed by a decimal index value enclosed in\n"
			"  square brackets '[' and ']'.\n"
			"\n"
			"Options:\n"
			" -h       Print this help message.\n"
			" -H num   Skip num first bytes.\n"
			" -e       Print TLV header.\n"
			" -n       Print TLV path. Has no effect with -r.\n"
			" -r       Print raw TLV (will override -n and -i).\n"
			" -i       Print TLV indexes in path.\n"
			" -v       TLV utility package version.\n"
			"\n"
			"Examples:\n"
			"  The following example will print out all the hash chain links in\n"
			"  the second aggregation chain\n\n"
			"    $ gttlvgrep 800.801[1].07,08\n\n");

}

int main(int argc, char **argv) {

	struct conf_st conf;

	FILE *f = NULL;
	int c;

	memset(&conf, 0, sizeof(conf));

	/* Default conf. */
	conf.print_raw = false;
	conf.print_path = true;
	conf.print_tlv_hdr = false;

	if (argc < 2) {
		printHelp(stderr);
		exit(1);
	}

	while ((c = getopt(argc, argv, "hH:enriv")) != -1) {
		switch(c) {
			case 'h':
				printHelp(stdout);
				exit(0);
			case 'H':
				conf.magic_len = atoi(optarg);
				break;
			case 'e':
				conf.print_tlv_hdr = true;
				break;
			case 'n':
				conf.print_path = true;
				break;
			case 'r':
				conf.print_raw = true;
				conf.print_path = false;
				break;
			case 'i':
				conf.print_path_index = true;
				break;
			case 'v':
				printf("%s\n", TLV_UTIL_VERSION_STRING);
				exit(0);
			default:
				fprintf(stderr, "Invalid option '%c'\n", c);
		}
	}

	if ( optind >= argc) {
		fprintf(stderr, "Error: no pattern provided!\n");
		exit(1);
	}

	conf.pattern = argv[optind++];

	if (optind >= argc) {
		f = stdin;
		conf.file_name = "<stdin>";
		grepFile(&conf, f);
	} else {
		for (; optind < argc; optind++) {
			conf.file_name = argv[optind];
			f = fopen(conf.file_name, "rb");
			if (!f) {
				fprintf(stderr, "%s: Unable to open file.\n", conf.file_name);
			}

			if (conf.magic_len) {
				if( fseek(f, conf.magic_len, SEEK_SET)) {
					fprintf(stderr, "%s: Unable to skip header.\n", conf.file_name);
					goto cleanup;
				}
			}

			grepFile(&conf, f);

			fclose(f);
			f = NULL;
		}
	}

cleanup:

	if (f != NULL) fclose(f);

}
