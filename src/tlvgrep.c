#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#	include <io.h>
#	include <fcntl.h>
#endif

#include "fast_tlv.h"
#include "grep_tlv.h"
#include "file_io.h"


static int grepFile(GT_GrepTlvConf *conf, FILE *f) {
	int res = GT_OK;
	GT_FTLV t;
	GT_ElementCounter *idx = NULL;
	size_t len = 0;
	size_t off = 0;

	long read_len;
	unsigned char *ptr = NULL;
	size_t global_off = 0;

	idx = calloc(sizeof(GT_ElementCounter), 1);
	if (idx == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	read_len = conf->consume_stream(&ptr, 0, f);
	if (read_len < 0 || (read_len == 0 && !feof(f))) {
		res = GT_IO_ERROR;
		goto cleanup;
	}
	len = read_len;

	/* Handle binary TLV data. */
	while (1) {
		size_t consumed;

		/* Try to read the next TLV. */
		res = GT_FTLV_memRead(ptr + off, len - off, &t);
		consumed = t.hdr_len + t.dat_len;
		t.off = global_off + off;

		if (((res != GT_OK) || (len - off < 2) || ((res == GT_OK) && (consumed > len - off))) && off != 0) {
			/* We have reached the end of the buffer, we need to shift. */
			read_len = conf->consume_stream(&ptr, off, f);
			if (read_len < 0 || (read_len == 0 && !feof(f))) {
				print_error("Error reading input.\n");
				res = GT_IO_ERROR;
				goto cleanup;
			}
			len = read_len;
			global_off += off;
			off = 0;

			continue;
		}

		/* If the code did not enter the previous block, exit if there's nothing left to do. */
		if (len == off) {
			break;
		}

		if (res != GT_OK || consumed > len - off) {
			print_error("%s: Failed to parse %llu bytes.\n", conf->file_name, (unsigned long long) len - off);
			res = GT_PARSER_ERROR;
			goto cleanup;
		}

		res = GT_grepTlv(conf, conf->pattern, NULL, idx, ptr + off, &t, NULL, NULL);
		if (res != GT_OK) goto cleanup;

		off += consumed;
	}

	res = GT_OK;

cleanup:

	free(idx);

	return res;
}


void printHelp(FILE *f) {
	fprintf(f,
			"Usage:\n"
			"  gttlvgrep [-h] [-v] [options] pattern [tlvfile...]\n"
			"\n"
			"Pattern:\n"
			"  The hierarchy of nested TLVs can be expressed by separating each level with a\n"
			"  dot '.' Multiple TLV types can be specified at each level by separating them\n"
			"  with comma ','. In case there are multiple instances of the same TLV type, a\n"
			"  0-based index can be used after the TLV type to return the specific instance\n"
			"  only. Example: '800.801[1].07,08' will return the TLV types 07 and 08 that are\n"
			"  nested inside the second instance of TLV type 801 inside TLV 800.\n"
			"\n"
			"Options:\n"
			" -h       Print help text.\n"
			" -H int   Ignore specified number of bytes in the beginning of input.\n"
			" -e       Print TLV type and length in addition to value.\n"
			" -r       Print raw (binary) TLV (will cancel -n and -i).\n"
			" -n       Print path of TLV type in human-readable format (has no effect with\n"
			"          -r).\n"
			" -i       Print index of the TLV element (has no effect without -n).\n"
			" -E enc   Input data encoding. Available: 'bin', 'hex', 'base64'.\n"
			" -v       Print TLV utility version.\n"
			"\n");

}

int main(int argc, char **argv) {
	int res = GT_UNKNOWN_ERROR;
	GT_GrepTlvConf conf;

	FILE *f = NULL;
	int c;

	/* Default conf. */
	GT_GrepTlv_initConf(&conf);
	conf.consume_stream = GT_consume_raw;
	conf.pattern = NULL;

	if (argc < 2) {
		printHelp(stderr);
		res = GT_INVALID_CMD_PARAM;
		goto cleanup;
	}

	while ((c = getopt(argc, argv, "hH:oenriT:L:vE:")) != -1) {
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
				setBinaryMode(stdout);
				break;
			case 'i':
				conf.print_path_index = true;
				break;
			case 'E':
				switch(conf.in_enc = GT_ParseEncoding(optarg)) {
					case GT_BASE_2:
						conf.consume_stream = GT_consume_raw;
						break;
					case GT_BASE_16:
						conf.consume_stream = GT_consume_hex;
						break;
					case GT_BASE_64:
						conf.consume_stream = GT_consume_b64;
						break;
					default:
						print_error("Unknown input data encoding: '%s'\n", optarg);
						res = GT_INVALID_CMD_PARAM;
						goto cleanup;
				}
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
	} else if (*(argv[optind]) == '\0') {
		fprintf(stderr, "Invalid pattern: the pattern must not be empty.\n");
		res = GT_INVALID_CMD_PARAM;
		goto cleanup;
	}

	res = GT_GrepPattern_parse(argv[optind++], &conf.pattern);
	if (res != GT_OK) {
		goto cleanup;
	}

	if (optind >= argc) {
		if (conf.in_enc == GT_BASE_2) setBinaryMode(stdin);
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

	GT_GrepPattern_free(conf.pattern);

	if (f != NULL && f != stdin) fclose(f);

	return res;
}
