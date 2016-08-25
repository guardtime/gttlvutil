#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "fast_tlv.h"
#include "grep_tlv.h"


static int grepFile(GT_GrepTlvConf *conf, FILE *f) {
	int res = GT_OK;
	GT_FTLV t;
	size_t len;
	unsigned char buf[0xffff + 4];
	int idx[IDX_MAP_LEN];

	memset(idx, 0, sizeof(idx));

	while (!feof(f)) {
		res = GT_FTLV_fileRead(f, buf, sizeof(buf), &len, &t);
		if (len == 0) {
			/* Reached the end of file. */
			res = GT_OK;
			break;
		}
		if (res != GT_OK) {
			fprintf(stderr, "%s: Failed to parse TLV.\n", conf->file_name);
			return res;
		}

		res = GT_grepTlv(conf, conf->pattern, NULL, idx, buf, &t, NULL, NULL);
		if (res != GT_OK) return res;
	}
	return res;
}


void printHelp(FILE *f) {
	fprintf(f,
			"Usage:\n"
			"  gttlvgrep <options> [pattern] <[tlv file]>\n"
			"\n"
			"Pattern:\n"
			"  The pattern describes the hierarchy of the element or elements\n"
			"  that the user is looking for. The path describes the TLV values\n"
			"  in layers of the TLV tree, starting from the outermost. Each level\n"
			"  is separated by a dot '.'. Each layer may contain one or multiple\n"
			"  TLV tag value(s). Multiple values are separated by a comma ','.\n"
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
			"  the second aggregation hash chain.\n\n"
			"    $ gttlvgrep 800.801[1].07,08\n"
			"\n");

}

int main(int argc, char **argv) {
	int res = GT_UNKNOWN_ERROR;
	GT_GrepTlvConf conf;

	FILE *f = NULL;
	int c;

	if (argc < 2) {
		printHelp(stderr);
		res = GT_INVALID_CMD_PARAM;
		goto cleanup;
	}

	/* Default conf. */
	GT_GrepTlv_initConf(&conf);

	while ((c = getopt(argc, argv, "hH:oenriT:L:v")) != -1) {
		switch(c) {
			case 'H':
				conf.magic_len = atoi(optarg);
				break;
			case 'o':
				conf.print_tlv_hdr_only = true;
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

			case 'h':
				printHelp(stdout);
				res = GT_OK;
				goto cleanup;
			case 'v':
				printf("%s\n", TLV_UTIL_VERSION_STRING);
				res = GT_OK;
				goto cleanup;
			default:
				fprintf(stderr, "Unknown parameter, try -h.\n");
				res = GT_INVALID_CMD_PARAM;
				goto cleanup;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: no pattern provided!\n");
		res = GT_INVALID_CMD_PARAM;
		goto cleanup;
	}

	conf.pattern = argv[optind++];

	if (optind >= argc) {
		f = stdin;
		conf.file_name = "<stdin>";
		res = grepFile(&conf, f);
		if (res != GT_OK) goto cleanup;
	} else {
		for (; optind < argc; optind++) {
			conf.file_name = argv[optind];
			f = fopen(conf.file_name, "rb");
			if (!f) {
				fprintf(stderr, "%s: Unable to open file.\n", conf.file_name);
				continue;
			}

			if (conf.magic_len) {
				if (fseek(f, conf.magic_len, SEEK_SET)) {
					fprintf(stderr, "%s: Unable to skip header.\n", conf.file_name);
					res = GT_IO_ERROR;
					goto cleanup;
				}
			}

			res = grepFile(&conf, f);
			if (res != GT_OK) goto cleanup;

			fclose(f);
			f = NULL;
		}
	}

	res = GT_OK;

cleanup:
	if (f != NULL && f != stdin) fclose(f);

	return res;
}
