#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <limits.h>
#ifdef _WIN32
#	include <io.h>
#	include <fcntl.h>
#endif
#include <string.h>

#include "file_io.h"

struct conf_st {
	int type;
	int non_critical;
	int forward;
	GT_Encoding in_enc;
	char *in_file;
};

int encode(struct conf_st *conf, FILE *in, FILE *out) {
	int res = GT_UNKNOWN_ERROR;
	unsigned char *buf = NULL;
	unsigned char hdr[4];
	size_t len = 0;

	if ((res = GT_fread(conf->in_enc, &buf, &len, in)) != GT_OK) goto cleanup;

	if (len >> 8 > UCHAR_MAX) {
		res = GT_INVALID_FORMAT;
		fprintf(stderr, "The size of the TLV payload is too great: '%llu'.\n", (unsigned long long)len);
		goto cleanup;
	}

	/* TLV 18? */
	if (conf->type > GT_TLV_TYPE_1ST_BYTE_MASK || len > 0xff) {
		*hdr = GT_TLV_MASK_TLV16 | (conf->non_critical * GT_TLV_MASK_NON_CRITICAL) | (conf->forward * GT_TLV_MASK_FORWARD) | (conf->type >> 8);
		*(hdr + 1) = conf->type & 0xff;
		*(hdr + 2) = (unsigned char)(len >> 8);
		*(hdr + 3) = len & 0xff;
		if (fwrite(hdr, 1, 4, out) != 4) {
			fprintf(stderr, "Failed to write to stream.");
			res = GT_IO_ERROR;
			goto cleanup;
		}
	} else {
		*hdr = (conf->non_critical * GT_TLV_MASK_NON_CRITICAL) | (conf->forward * GT_TLV_MASK_FORWARD) | (conf->type);
		*(hdr + 1) = len & 0xff;
		if (fwrite(hdr, 1, 2, out) != 2) {
			fprintf(stderr, "Failed to write to stream.");
			res = GT_IO_ERROR;
			goto cleanup;
		}
	}

	if (fwrite(buf, 1, len, out) != len) {
		fprintf(stderr, "Failed to write to stream.");
		res = GT_IO_ERROR;
		goto cleanup;
	}

	res = GT_OK;

cleanup:

	free(buf);

	return res;
}

void printHelp(FILE *f) {
	fprintf(f,
		"Usage:\n"
		"  gttlvwrap [-h] [-v] [options] -t type [-i input] [-o output]\n\n"
		"Options:\n"
		"  -h         Print help text.\n"
		"  -t type    TLV type in hex.\n"
		"  -N         Set the TLV Non-Critical flag.\n"
		"  -F         Set the TLV Forward Unknown Flag.\n"
		"  -i file    Input file that is going to be wrapped with TLV header.\n"
		"  -E enc     Input data encoding. Available: 'bin', 'hex', 'base64'.\n"
		"  -o file    Output file for generated TLV.\n"
		"  -v         Print TLV utility version.\n"
		"\n");
}

int main(int argc, char **argv) {
	int res = GT_UNKNOWN_ERROR;
	int c;
	FILE *in = NULL;
	FILE *out = NULL;
	struct conf_st conf;

	conf.type = -1;
	conf.non_critical = 0;
	conf.forward = 0;
	conf.in_enc = GT_BASE_2;
	conf.in_file = NULL;


	while ((c = getopt(argc, argv, "LNFt:i:o:hvE:")) != -1) {
		switch (c) {
			case 'L':
				fprintf(stderr, "Warning: -L is deprecated, use -N instead for Non-Critical flag.\n");
			case 'N':
				conf.non_critical = 1;
				break;
			case 'F':
				conf.forward = 1;
				break;
			case 't': {
					char *tail = NULL;
					conf.type = strtol(optarg, &tail, 16);
					if (*tail != 0) {
						fprintf(stderr, "Bad tag value: '%s'.", optarg);
						res = GT_INVALID_CMD_PARAM;
						goto cleanup;
					}
					if (conf.type <= 0 || conf.type > 0x1fff) {
						fprintf(stderr, "Tag value out of range.");
						res = GT_INVALID_CMD_PARAM;
						goto cleanup;
					}
				}
				break;
			case 'E':
				conf.in_enc = GT_ParseEncoding(optarg);
				if (conf.in_enc == GT_BASE_NA) {
					fprintf(stderr, "Unknown input data encoding: '%s'\n", optarg);
					res = GT_INVALID_CMD_PARAM;
					goto cleanup;
				}
				break;
			case 'i':
				conf.in_file = calloc(strlen(optarg) + 1, sizeof(char));
				if (!conf.in_file) {
					res = GT_OUT_OF_MEMORY;
					goto cleanup;
				}
				strcpy(conf.in_file, optarg);
				break;
			case 'o':
				out = fopen(optarg, "wb");
				if (out == NULL) {
					fprintf(stderr, "Unable to open output file '%s'.\n", optarg);
					res = GT_IO_ERROR;
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

	if (conf.type < 0) {
		fprintf(stderr, "Tlv tag (-t) must be specified.\n");
		res = GT_INVALID_CMD_PARAM;
		goto cleanup;
	}

	if (conf.in_file) {
		in = fopen(conf.in_file, conf.in_enc == GT_BASE_2 ? "rb" : "r");
		if (in == NULL) {
			fprintf(stderr, "Unable to open input file '%s'.\n", conf.in_file);
			res = GT_IO_ERROR;
			goto cleanup;
		}
	} else {
		in = stdin;
	}

	if (out == NULL) {
		out = stdout;
		setBinaryMode(out);
	}

	res = encode(&conf, in, out);

cleanup:

	if (in != NULL && in != stdin) fclose(in);
	if (out != NULL && out != stdout) fclose(out);
	free(conf.in_file);

	return tlvutil_ErrToExitcode(res);
}
