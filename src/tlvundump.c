#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>

#include "common.h"

#ifdef _WIN32
#	include <io.h>
#	include <fcntl.h>
#endif

typedef struct {
	char buf[0xffff + 4];
	size_t len;
} Buffer;

size_t lineNr = 0;
size_t pos = 0;
char *fileName = "<stdin>";

enum {
	ST_BEGIN,
	ST_COMMENT,
	ST_FORCE,
	ST_FORCE_16,
	ST_RAW_CONTENT,
	ST_INDENT,
	ST_TLV_T,
	ST_TLV_L,
	ST_TLV_V,
	ST_BRACKET_BEGIN,
	ST_TAG_BEGIN,
	ST_TAG,
	ST_FLAG_START,
	ST_FLAG,
	ST_FLAG_END,
	ST_BRACKET_END,
	ST_COLON,
	ST_DATA,
	ST_DATA_STRING,
	ST_DATA_STRING_ESC,
	ST_DATA_STRING_DEC_1,
	ST_DATA_STRING_DEC_2,
	ST_DATA_STRING_DEC_3,
	ST_DATA_HEX_1,
	ST_DATA_HEX_2,
	ST_END,
};

typedef struct {
	char indent[1024];
	size_t indent_len;

	char dat[0xffff];
	size_t dat_len;

	int level;

	unsigned tag;
	int isFw;
	int isNc;

	int force;

	size_t lineNr;
	int headless;
} TlvLine;

#define line_error(err, s, lineNr) fprintf(stderr, "%s:%llu - %s\n", fileName, (unsigned long long)(lineNr), (s)); return err
#define error(err, s) line_error(err, (s), lineNr)
#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')
#define IS_DIGIT(c) ((c) >= '0' && (c) <= '9')
#define IS_HEX(c) (IS_DIGIT(c) || (toupper(c) >= 'A' && toupper(c) <= 'F'))
#define HEX_TO_DEC(c) (IS_DIGIT(c) ? ((c) - '0') : (toupper((c)) - 'A' + 10))

int parseTlv(FILE *f, TlvLine *tlv) {
	int state = ST_BEGIN;
	int c;

	memset(tlv, 0, sizeof(TlvLine));

	c = fgetc(f);
	pos = 1;
	lineNr++;
	while (1) {
		switch(state) {
			case ST_BEGIN:
				if (IS_HEX(c)) {
					state = ST_RAW_CONTENT;
					continue;
				}
				if (c == '\n') {
					/* Count newlines. */
					pos = 0;
					lineNr++;
					break;
				} else if (c == '\r') {
					/* If not carriage return, proceed to parse the indent. */
					break;
				} else if (c == EOF) {
					return GT_END_OF_STREAM; /* Indicate end of input. */
				} else {
					state = ST_INDENT;
					continue;
				}
				break;
			case ST_COMMENT:
				if (c == '\n') {
					state = ST_BEGIN;
				} else if (c == EOF) {
					state = ST_BEGIN;
					continue;
				}
				break;
			case ST_INDENT:
				if (c == ' ' || c == '\t') {
					tlv->indent[tlv->indent_len++] = c;
				} else if (c == '#') {
					state = ST_COMMENT;
					tlv->indent_len = 0;
				} else {
					state = ST_TLV_T;
					continue;
				}
				break;
			case ST_RAW_CONTENT:
				tlv->headless = 1;
				state = ST_DATA_HEX_1;
				continue;
			case ST_TLV_T:
				if (c != 'T') {
					error(GT_PARSER_ERROR, "Expected 'T'.");
				}
				state = ST_TLV_L;
				break;
			case ST_TLV_L:
				if (c != 'L') {
					error(GT_PARSER_ERROR, "Expected 'L'.");
				}
				state = ST_TLV_V;
				break;
			case ST_TLV_V:
				if (c != 'V') {
					error(GT_PARSER_ERROR, "Expected 'V'.");
				}
				state = ST_FORCE;
				break;
			case ST_FORCE:
				state = ST_BRACKET_BEGIN;
				if (c == '1') {
					state = ST_FORCE_16;
					break;
				} else if (c == '8') {
					tlv->force = 8;
				} else {
					continue;
				}
				break;
			case ST_FORCE_16:
				if (c != '6') {
					error(GT_PARSER_ERROR, "Expected '6'.");
				}
				tlv->force = 16;
				state = ST_BRACKET_BEGIN;
				break;
			case ST_BRACKET_BEGIN:
				if (IS_SPACE(c)) break;
				if (c != '[') {
					error(GT_PARSER_ERROR, "Expected '['.");
				}
				state = ST_TAG_BEGIN;
				break;
			case ST_TAG_BEGIN:
				if (IS_SPACE(c)) break;
				if (IS_HEX(c)) {
					state = ST_TAG;
					continue;
				} else {
					error(GT_PARSER_ERROR, "Expected hex tag value.");
				}
				break;
			case ST_TAG:
				if (IS_DIGIT(c)) {
					tlv->tag = tlv->tag << 4 | ( c - '0');
				} else if (toupper(c) >= 'A' && toupper(c) <= 'F') {
					tlv->tag = (tlv->tag << 4) | (toupper(c) - 'A' + 10);
				} else {
					state = ST_FLAG_START;
					continue;
				}

				/* Make sure the tag value does not overflow. */
				if (tlv->tag > 0x1fff) {
					error(GT_PARSER_ERROR, "TLV tag value may not exceed 0x1fff.");
				}
				break;
			case ST_FLAG_START:
				if (IS_SPACE(c)) break;
				if (c == ',') {
					state = ST_FLAG;
				} else {
					state = ST_FLAG_END;
					continue;
				}
				break;
			case ST_FLAG:
				if (IS_SPACE(c)) break;
				switch(toupper(c)) {
					case 'F':
						tlv->isFw = 1;
						break;
					case 'N':
						tlv->isNc = 1;
						break;
					default:
						error(GT_PARSER_ERROR, "Unexpected flag.");
						break;
				}

				state = ST_FLAG_END;
				break;
			case ST_FLAG_END:
				if (IS_SPACE(c)) break;
				if (c == ',') {
					state = ST_FLAG_START;
					continue;
				} else {
					state = ST_BRACKET_END;
					continue;
				}
				break;
			case ST_BRACKET_END:
				if (IS_SPACE(c)) break;
				if (c != ']') {
					error(GT_PARSER_ERROR, "Expected ']'.");
				}
				state = ST_COLON;
				break;
			case ST_COLON:
				if (IS_SPACE(c)) break;
				if (c != ':') {
					error(GT_PARSER_ERROR, "Expected ':'.");
				}

				state = ST_DATA;
				break;
			case ST_DATA:
				if (IS_SPACE(c)) break;
				if (c == '"') {
					state = ST_DATA_STRING;
				} else if (c == '\n' || c == EOF) {
					state = ST_END;
					continue;
				} else {
					state = ST_DATA_HEX_1;
					continue;
				}
				break;
			case ST_DATA_STRING:
				if (c == '\\') {
					state = ST_DATA_STRING_ESC;
					break;
				} else if (c == '"') {
					state = ST_END;
					break;
				} else {
					if (tlv->dat_len >= sizeof(tlv->dat)) {
						error(GT_PARSER_ERROR, "String value too large.");
					}
					tlv->dat[tlv->dat_len++] = c;
				}
				break;
			case ST_DATA_STRING_ESC:
				if (IS_DIGIT(c)) {
					state = ST_DATA_STRING_DEC_1;
					continue;
				} else if (c == EOF) {
					error(GT_PARSER_ERROR, "Unexpected end of file.");
				}
				tlv->dat[tlv->dat_len++] = c;
				state = ST_DATA_STRING;
				break;
			case ST_DATA_STRING_DEC_1:
				tlv->dat[tlv->dat_len] = (c - '0');
				state = ST_DATA_STRING_DEC_2;
				break;
			case ST_DATA_STRING_DEC_2:
				if (IS_DIGIT(c)) {
					tlv->dat[tlv->dat_len] = tlv->dat[tlv->dat_len] * 10 + (c - '0');
					state = ST_DATA_STRING_DEC_3;
				} else {
					tlv->dat_len++;
					state = ST_DATA_STRING;
					continue;
				}
				break;
			case ST_DATA_STRING_DEC_3:
				if (IS_DIGIT(c)) {
					tlv->dat[tlv->dat_len] = tlv->dat[tlv->dat_len] * 10 + (c - '0');
				}
				tlv->dat_len++;
				state = ST_DATA_STRING;
				if (!IS_DIGIT(c)) {
					continue;
				}
				break;
			case ST_DATA_HEX_1:
				if (IS_SPACE(c)) break;
				if (IS_HEX(c)) {
					tlv->dat[tlv->dat_len] = HEX_TO_DEC(c) << 4;
					state = ST_DATA_HEX_2;
				} else {
					state = ST_END;
					continue;
				}
				break;
			case ST_DATA_HEX_2:
				if (IS_SPACE(c)) break;
				if (IS_HEX(c)) {
					tlv->dat[tlv->dat_len++] |= HEX_TO_DEC(c);
					state = ST_DATA_HEX_1;
				} else {
					state = ST_END;
					tlv->dat_len++;
					continue;
				}
				break;
			case ST_END:
				if (IS_SPACE(c)) break;
				if (c == '\n' || c == EOF) {
					tlv->lineNr = lineNr;
					return GT_OK; /* Indicate success. */
				} else {
					error(GT_PARSER_ERROR, "Unexpected character.");
				}
				break;
			default:
				error(GT_PARSER_ERROR, "Unknown error.");
		}
		c = fgetc(f);
		pos++;
	}

	error(GT_PARSER_ERROR, "Unknown format error.");
}

static int serializeStack(TlvLine *stack, size_t stack_len, unsigned char *buf, size_t buf_len, size_t *total_len) {
	int res = GT_UNKNOWN_ERROR;
	size_t i;
	size_t len = 0;
	size_t subLen = 0;

	/* Find the next occurrence of the same level of this branch. */
	for (i = 1; i < stack_len; i++) {
		if (stack[0].level > stack[i].level) break;
		if (stack[0].level == stack[i].level) {
			res = serializeStack(stack + i, stack_len - i, buf, buf_len, &len);
			break;
		}
	}

	/* Serialize only the next level elements of this branch. Note, the function is
	* recursive, so we need to serialize only the first one. */
	if (stack_len > 1 && stack[0].level < stack[1].level) {
		res = serializeStack(stack + 1, stack_len - 1, buf, buf_len - len, &subLen);
		len += subLen;
	}

	/* Serialize payload. */
	if (stack[0].dat_len > 0) {
		if (subLen != 0) {
			line_error(GT_INVALID_FORMAT, "Length should be 0 when not a composite.", stack[0].lineNr);
		}
		memcpy(buf + buf_len - len - stack[0].dat_len, stack[0].dat, stack[0].dat_len);
		len += subLen = stack[0].dat_len;
	}

	/* Skip the header, if the TLV is headless. */
	if (stack[0].headless) {
		res = GT_OK;
		goto cleanup;
	}

	if (stack[0].tag > 0x1f || subLen > 0xff || stack[0].force == 16) {
		/* TLV16 */
		if (buf_len - len < 4) {
			line_error(GT_BUFFER_OVERFLOW, "TLV16 buffer overflow.", stack[0].lineNr);
		}

		if (stack[0].force == 8) {
			line_error(GT_INVALID_FORMAT, "Unable to fit data into TLV8.", stack[0].lineNr);
		}
		buf[buf_len - len - 1] = subLen & 0xff;
		buf[buf_len - len - 2] = (subLen >> 8) & 0xff;
		buf[buf_len - len - 3] = stack[0].tag & 0xff;
		buf[buf_len - len - 4] = (stack[0].tag >> 8) & 0x1f;
		len += 4;

		buf[buf_len - len] |= 0x80;

	} else {
		if (buf_len - len < 2) {
			line_error(GT_BUFFER_OVERFLOW, "TLV8 buffer overflow.", stack[0].lineNr);
		}
		buf[buf_len - len - 1] = subLen & 0xff;
		buf[buf_len - len - 2] = stack[0].tag & 0x1f;
		len += 2;
	}

	if (stack[0].isNc) buf[buf_len - len] |= 0x40;
	if (stack[0].isFw) buf[buf_len - len] |= 0x20;

	res = GT_OK;
cleanup:
	if (total_len) *total_len = len;

	return res;
}

static int writeStream(const void *raw, size_t size, size_t count, FILE *f) {
#ifdef _WIN32
	if (f != NULL) {
		_setmode(_fileno(f), _O_BINARY);
	}
#endif

	if (fwrite(raw, size, count, f) != count) {
		error(GT_IO_ERROR, "Failed to write to stream.");
	}

	return GT_OK;
}

static int convertStream(FILE *f) {
	int res = GT_UNKNOWN_ERROR;
	TlvLine *stack = NULL;
	size_t stack_size = 100;
	size_t stack_len = 0;
	size_t i;

	stack = calloc(stack_size, sizeof(TlvLine));
	if (stack == NULL) {
		fprintf(stderr, "Out of memory!\n");
		return GT_OUT_OF_MEMORY;
	}

	while (1) {
		res = parseTlv(f, &stack[stack_len]);
		if (res == GT_END_OF_STREAM) break;
		else if (res != GT_OK) goto cleanup;

		/* The variable stack_len is the index of the last element and is incremented
		 * in the end of this loop. */
		if (stack_len == 0 || stack[stack_len].indent_len == 0) {
			stack[stack_len].level = 0;
		} else {
			if (stack[stack_len].indent_len < stack[stack_len - 1].indent_len) {
				stack[stack_len].level = -1;

				for (i = stack_len; i > 0; i--) {
					if (stack[stack_len].indent_len > stack[i - 1].indent_len) {
						error(GT_INVALID_FORMAT, "Bad backwards indentation - no matching level.");
					} else if (stack[stack_len].indent_len == stack[i - 1].indent_len) {
						if (memcmp(stack[stack_len].indent, stack[i - 1].indent, stack[stack_len].indent_len)) {
							error(GT_INVALID_FORMAT, "Bad backwards indentation - whitespace mismatch.");
						}
						stack[stack_len].level = stack[i - 1].level;
						break;
					}
				}

				if (stack[stack_len].level < 0) {
					error(GT_INVALID_FORMAT, "Bad backwards indentation - previous level not found.");
				}
			} else {
				/* Make sure the indentation matches. */
				if (memcmp(stack[stack_len].indent, stack[stack_len - 1].indent, stack[stack_len - 1].indent_len)) {
					error(GT_INVALID_FORMAT, "Indentation not a subset.");
				}

				stack[stack_len].level = stack[stack_len - 1].level;

				if (stack[stack_len].indent_len > stack[stack_len - 1].indent_len) {
					/* A subset of the previous. */
					if (stack[stack_len - 1].dat_len > 0) {
						error(GT_INVALID_FORMAT, "A TLV with explicit data may not have nested elements.");
					}
					stack[stack_len].level++;
				}

			}
		}

		/* Serialize the TLV if there level returned to 0. */
		if (stack_len != 0 && stack[stack_len].level == 0) {
			unsigned char buf[0xffff + 4];
			size_t buf_len = 0;

			res = serializeStack(stack, stack_len, buf, sizeof(buf), &buf_len);
			if (res != GT_OK) goto cleanup;

			res = writeStream(buf + sizeof(buf) - buf_len, 1, buf_len, stdout);
			if (res != GT_OK) goto cleanup;

			stack[0] = stack[stack_len];
			stack_len = 1;

		} else {
			stack_len++;
		}

		/* Sanity check. */
		if (stack_len >= stack_size) {
			TlvLine *tmp = NULL;
			stack_size += 100;

			tmp = realloc(stack, stack_size * sizeof(TlvLine));
			if (tmp == NULL) {
				error(GT_OUT_OF_MEMORY, "Unable to reallocate internal buffer.");
			}
			stack = tmp;
		}
	}

	if (stack_len > 0) {
		unsigned char buf[0xffff + 4];
		size_t buf_len = 0;

		res = serializeStack(stack, stack_len, buf, sizeof(buf), &buf_len);
		if (res != GT_OK) goto cleanup;

		res = writeStream(buf + sizeof(buf) - buf_len, 1, buf_len, stdout);
		if (res != GT_OK) goto cleanup;
	}
	res = GT_OK;
cleanup:
	if (stack != NULL) free(stack);
	return res;
}

int main(int argc, char **argv) {
	int res = GT_UNKNOWN_ERROR;
	FILE *f = NULL;
	int c;

	while ((c = getopt(argc, argv, "hv")) != -1) {
		switch(c) {
			case 'h':
				printf("Usage:\n"
						"  gttlvundump [-h] tlvfile\n"
						"    -h       This help message.\n"
						"    -v       TLV utility package version.\n"
				);
				exit(0);
			case 'v':
				printf("%s\n", TLV_UTIL_VERSION_STRING);
				exit(0);
			default:
				fprintf(stderr, "Unknown parameter, try -h.");
				exit(1);
		}
	}

	/* If there are no input files, read from the standard in. */
	if (optind >= argc) {
		res = convertStream(stdin);
		if (res != GT_OK) goto cleanup;
	} else {
		int i;

		/* Loop over all the inputfiles. */
		for (i = 0; optind + i < argc; i++) {
			fileName = argv[optind + i];

			f = fopen(fileName, "rb");
			if (f == NULL) {
				fprintf(stderr, "%s: Unable to open file.\n", fileName);
				continue;
			}

			res = convertStream(f);
			if (res != GT_OK) goto cleanup;

			fclose(f);
			f = NULL;
		}
	}

cleanup:
	if (f != NULL && f != stdin) fclose(f);

	return 0;
}

