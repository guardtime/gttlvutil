#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <stdbool.h>
#include <limits.h>

#include "gt_tlv.h"
#include "common.h"

/*
 * Dump number of hex encoded bytes into stream.
 */
static void dumpBytesHex(FILE *f, const uint8_t *data, const size_t data_length) {
	size_t i;
	for (i = 0; i < data_length; i++) {
		fprintf(f, "%02x", *(data + i));
	}
}

/*
 * Concat two strings and return new string. The new string needs to
 * be freed by the user.
 */
char *strconcat(const char *str1, const char *str2) {
	char *str = NULL;

	str = malloc(strlen(str1) + strlen(str2) + 1);

	if (str != NULL) {
		sprintf(str, "%s%s", str1, str2);
	}

	return str;
}

/*
 * Dump number of bytes into stream. If a character is ASCII print the
 * corresponding character otherwise escape the numeric value with a
 * backslash.
 */
void dumpBytesAscii(FILE *f, const char *data, const size_t data_length) {
	size_t i;
	for (i = 0; i < data_length; i++) {
		if (isascii(*(data + i))) {
			fprintf(f,"%c", *(data + i));
		} else {
			fprintf(f,"\\%d", (unsigned char)*(data + i));
		}
	}
}

static bool isSubTlv(const uint8_t *data, const size_t data_length) {
	bool result = false;
	GTTlvReader *reader = NULL;
	GTTlv *tlv = NULL;

	if (data_length < 2) goto cleanup;

	if (GTTlvTReader_initMem(data, data_length, &reader) != GT_OK) goto cleanup;

	while (true) {
		if (GTTlvReader_readTlv(reader, &tlv) != GT_OK) goto cleanup;
		if (tlv == NULL) break;
		/* This setup is unlikely with Guardtime TLV's, but nevertheless is a hack. */
		if (tlv->type == 0 && tlv->payload_length == 0) goto cleanup;
		GTTlv_free(tlv);
		tlv = NULL;
	}
	result = true;
cleanup:
	GTTlvReader_free(reader);
	GTTlv_free(tlv);
	return result;
}

int dumpReader(int seek, char *prefix, int max_depth, GTTlvReader *reader) {
	int res = GT_UNKNOWN_ERROR;
	GTTlvReader *nestedReader = NULL;
	GTTlv *tlv = NULL;
	char *newPrefix = NULL;
	int relativeSeek;
	while (1) {
		relativeSeek = reader->relativeOffset;

		res = GTTlvReader_readTlv(reader, &tlv);
		if (res != GT_OK) {
			if (tlv != NULL) {
				int i;
				/* Assume we have the header. */
				fprintf(stderr, "Invalid header: ");
				for (i = 0; i < tlv->header_len; i++) {
					fprintf(stderr, "%02x ", tlv->header[i]);
				}
				fprintf(stderr, "\n");
			}
			goto cleanup;
		}

		if (tlv == NULL) {
			res = GT_OK;
			goto cleanup;
		}

		printf("%4d:", seek + relativeSeek);
		if (tlv->type < 0xff) {
			printf("%sTLV[0x%02x] ",prefix, tlv->type);
		} else {
			printf("%sTLV[0x%04x] ",prefix, tlv->type);
		}
		printf("%c%c len = %lu: ", GT_is_tlv_flag_lenient(tlv) ? 'L' : '-', GT_is_tlv_flag_forward(tlv) ? 'F' : '-', tlv->payload_length);
		if (max_depth > 0 && isSubTlv(tlv->payload, tlv->payload_length)) {
			newPrefix = strconcat(prefix, "    ");
			printf("\n");
			res = GTTlvTReader_initMem(tlv->payload, tlv->payload_length, &nestedReader);
			if (res != GT_OK) {
				goto cleanup;
			}
			dumpReader(seek + relativeSeek + tlv->header_len, newPrefix, max_depth - 1, nestedReader);
			GTTlvReader_free(nestedReader);
			nestedReader = NULL;
			free(newPrefix);
			newPrefix = NULL;
		} else {
			if (tlv->payload_length < 40) {
				dumpBytesHex(stdout, tlv->payload, tlv->payload_length);
			} else {
				newPrefix = strconcat(prefix, "          ");

				int i;
				for (i = 0; i < tlv->payload_length; i++) {
					if (i % 40 == 0) printf("\n%s", newPrefix);
					printf("%02x ", *(tlv->payload + i));
				}

				free(newPrefix);
				newPrefix = NULL;
			}
			printf("\n");
		}

		GTTlv_free(tlv);
		tlv = NULL;
	}
cleanup:
	GTTlvReader_free(nestedReader);
	GTTlv_free(tlv);
	free(newPrefix);
	return res;
}

int main(int argc, char **argv) {
	int res = GT_UNKNOWN_ERROR;
	char *header = NULL;
	int header_len = 0;
	int max_depth = INT_MAX;
	FILE *input = NULL;
	GTTlvReader *reader = NULL;
	int c;

	while ((c = getopt(argc, argv, "hH:d:")) != -1) {
		switch(c) {
			case 'H':
				header_len = atoi(optarg);
				break;
			case 'h':
				printf("Usage:\n"
						"  gttlvdump [-h] [-H number] tlvfile\n"
						"    -h      This help message\n"
						"    -H num  Constant header lenght.\n"
						"    -d num  Max depth of nested elements\n");
				res = GT_OK;
				goto cleanup;
			case 'd':
				max_depth = atoi(optarg);
				break;	
			default:
				fprintf(stderr, "Unknown parameter, try -h.");
				goto cleanup;
		}
	}

	if (optind + 1 == argc) {
		if ((input = fopen(argv[optind], "rb")) == NULL) {
			fprintf(stderr, "Unable to open file %s\n", argv[1]);
			res = GT_IO_ERROR;
			goto cleanup;
		}
	} else if (optind >= argc){
		input = stdin;
	} else {
		fprintf(stderr, "Unknown parameters, try -h\n");
		goto cleanup;
	}

	if (header_len > 0) {
		header = calloc(header_len, 1);
		if (fread(header, header_len, 1, input) != 1) {
			res = GT_FORMAT_ERROR;
			goto cleanup;
		}
		printf("Header: ");
		dumpBytesAscii(stdout, header, header_len);
		printf("\n");

	}
	res = GTTlvTReader_initFile(input, &reader);

	res = dumpReader(0, "", max_depth, reader);

	if (res != GT_OK) {
		goto cleanup;
	}

	res = GT_OK;

cleanup:
   if (input != stdin) {
		fclose(input);
   }
   free(header);
   GTTlvReader_free(reader);
   return res;
}

