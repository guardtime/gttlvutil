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
		if (len == 0) break;

		if (res != GT_OK) {
			fprintf(stderr, "%s: Failed to parse TLV.\n", conf->file_name);
			return GT_FORMAT_ERROR;
		}

		res = GT_grepTlv(conf, conf->pattern, NULL, idx, buf, &t, NULL, NULL);
	}
	return res;
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
			" -P       Print header.\n"
			" -e       Print TLV header.\n"
			" -n       Print TLV path. Has no effect with -r.\n"
			" -r       Print raw TLV (will override -n and -i).\n"
			" -i       Print TLV indexes in path.\n"
			" -T tag   TLV tag hex value representation, which data will be truncated to the lenght defined by -L\n"
			" -L num   Set lenght of data bytes to be printed (valid with -T).\n"
			" -v       TLV utility package version.\n"
			"\n"
			"Examples:\n"
			"  The following example will print out all the hash chain links in\n"
			"  the second aggregation chain\n\n"
			"    $ gttlvgrep 800.801[1].07,08\n\n");

}

int main(int argc, char **argv) {

	GT_GrepTlvConf conf;

	FILE *f = NULL;
	int c;

	if (argc < 2) {
		printHelp(stderr);
		exit(1);
	}

	/* Default conf. */
	GT_GrepTlv_initConf(&conf);

	while ((c = getopt(argc, argv, "hH:oenriT:L:v")) != -1) {
		switch(c) {
			case 'h':
				printHelp(stdout);
				exit(0);
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
			case 'T':
				conf.trunc_tlv_tag = strtol(optarg, NULL, 16);
				break;
			case 'L':
				conf.trunc_len = atoi(optarg);
				break;
			case 'v':
				printf("%s\n", TLV_UTIL_VERSION_STRING);
				exit(0);
			default:
				fprintf(stderr, "Invalid option '%c'\n", c);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: no pattern provided!\n");
		exit(1);
	}

	conf.pattern = argv[optind++];

	if (optind >= argc) {
		f = stdin;
		conf.file_name = "<stdin>";
		if (grepFile(&conf, f) != GT_OK) goto cleanup;
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
					goto cleanup;
				}
			}

			if (grepFile(&conf, f) != GT_OK) {
				goto cleanup;
			}

			fclose(f);
			f = NULL;
		}
	}

cleanup:
	if (f != NULL && f != stdin) fclose(f);

	return 0;
}
