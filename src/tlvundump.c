#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"


typedef struct {
	char buf[0xffff + 4];
	size_t len;
} Buffer;

size_t lineNr = 0;
size_t pos = 0;
char *fileName = "<stdin>";

enum {
	ST_BEGIN,
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
	ST_DATA_STRING_OCT_1,
	ST_DATA_STRING_OCT_2,
	ST_DATA_STRING_OCT_3,
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
	int isNested;
} TlvLine;

#define error(s) fprintf(stderr, "%s:%d:%d - %s\n", fileName, lineNr,pos, s); exit(2)
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
				if (c == '\n') {
					/* Count newlines. */
					pos = 0;
					lineNr++;
					break;
				} else if (c == '\r') {
					/* If not carriage return, proceed to parse the indent. */
					break;
				} else if (c == EOF) {
					return 0; /* Indicate end of input. */
				} else {
					state = ST_INDENT;
					continue;
				}
			case ST_INDENT:
				if (c == ' ' || c == '\t') {
					tlv->indent[tlv->indent_len++] = c;
				} else {
					state = ST_TLV_T;
					continue;
				}
				break;
			case ST_TLV_T:
				if (c != 'T') {
					error("Expected 'T'");
				}
				state = ST_TLV_L;
				break;
			case ST_TLV_L:
				if (c != 'L') {
					error("Expected 'L'");
				}
				state = ST_TLV_V;
				break;
			case ST_TLV_V:
				if (c != 'V') {
					error("Expected 'V'");
				}
				state = ST_BRACKET_BEGIN;
				break;
			case ST_BRACKET_BEGIN:
				if (IS_SPACE(c)) break;
				if (c != '[') {
					error("Expected '['");
				}
				state = ST_TAG_BEGIN;
				break;
			case ST_TAG_BEGIN:
				if (IS_SPACE(c)) break;
				if (IS_HEX(c)) {
					state = ST_TAG;
					continue;
				} else {
					error("Expected hex tag value.");
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
					error("TLV tag value may not exceed 0x1fff");
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
					case 'L':
						tlv->isNc = 1;
						break;
					default:
						error("Unexpected flag.");
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
					error("Expected ']'");
				}
				state = ST_COLON;
				break;
			case ST_COLON:
				if (IS_SPACE(c)) break;
				if (c != ':') {
					error("Expected ':'");
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
						error("String value too lagre.");
					}
					tlv->dat[tlv->dat_len++] = c;
				}
				break;
			case ST_DATA_STRING_ESC:
				if (IS_DIGIT(c)) {
					state = ST_DATA_STRING_OCT_1;
					continue;
				} else if (c == EOF) {
					error("Unexpected end of file.");
				}
				tlv->dat[tlv->dat_len++] = c;
				break;
			case ST_DATA_STRING_OCT_1:
				tlv->dat[tlv->dat_len] = (c - '0');
				state = ST_DATA_STRING_OCT_2;
				break;
			case ST_DATA_STRING_OCT_2:
				if (IS_DIGIT(c)) {
					tlv->dat[tlv->dat_len] = tlv->dat[tlv->dat_len] * 10 + (c - '0');
					state = ST_DATA_STRING_OCT_3;
				} else {
					tlv->dat_len++;
					state = ST_DATA_STRING;
					continue;
				}
				break;
			case ST_DATA_STRING_OCT_3:
				if (IS_DIGIT(c)) {
					tlv->dat[tlv->dat_len] = tlv->dat[tlv->dat_len] * 10 + (c - '0');
				}
				tlv->dat_len++;
				state = ST_DATA_STRING;
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
					return 1; /* Indicate success. */
				} else {
					error("Unexpected character.");
				}
				break;
			default:
				error("Unknown error.");
		}
		c = getc(f);
		pos++;
	}

	error("Unknown format error.");
}

static size_t serializeStack(TlvLine *stack, size_t stack_len, char *buf, size_t buf_len) {
	size_t i;
	size_t len = 0;
	size_t subLen = 0;

	/* Find the next occurrance of the same level of this branch. */
	for (i = 1; i < stack_len; i++) {
		if (stack[0].level > stack[i].level) break;
		if (stack[0].level == stack[i].level) {
			len = serializeStack(stack + i, stack_len - i, buf, buf_len);
			break;
		}
	}

	/* Serialize only the next level elements of this branch. Note, the function is 
 	* recursive, so we need to serialize only the first one. */
	if (stack_len > 1 && stack[0].level < stack[1].level) {
		len += subLen = serializeStack(stack + 1, stack_len - 1, buf, buf_len - len);
	}

	/* Serialize payload. */
	if (stack[0].dat_len > 0) {
		if (subLen != 0) {
			error("Length sould be 0 when not a composite.");
		}
		memcpy(buf + buf_len - len - stack[0].dat_len, stack[0].dat, stack[0].dat_len);
		len += subLen = stack[0].dat_len;
	}

	if (stack[0].tag > 0x1f || subLen > 0xff) {
		/* TLV16 */
		if (buf_len - len < 4) {
			error("TLV16 buffer overflow.");
		}
		buf[buf_len - len - 1] = subLen & 0xff;
		buf[buf_len - len - 2] = (subLen >> 8) & 0xff;
		buf[buf_len - len - 3] = stack[0].tag & 0xff;
		buf[buf_len - len - 4] = (stack[0].tag >> 8) & 0x1f;
		len += 4;

		buf[buf_len - len] |= 0x80;

	} else {
		if (buf_len - len < 2) {
			error("TLV8 buffer overflow");
		}
		buf[buf_len - len - 1] = subLen & 0xff;
		buf[buf_len - len - 2] = stack[0].tag & 0x1f;
		len += 2;
	}

	if (stack[0].isNc) buf[buf_len - len] |= 0x40;
	if (stack[0].isFw) buf[buf_len - len] |= 0x20;

	return len;
}


int main(int argc, char **argv) {
	FILE *f = NULL;
	TlvLine *stack = NULL;
	size_t stack_size = 100;
	size_t stack_len = 0;
	size_t i;

	stack = calloc(stack_size, sizeof(TlvLine));
	if (stack == NULL) {
		fprintf(stderr, "Out of memory!\n");
		exit(1);
	}

	f = fopen(argv[1], "r");

	while (parseTlv(f, &stack[stack_len])) {
		/* The variable stack_len is the index of the last element and is incremented
		 * in the end of this loop. */
		if (stack_len == 0) {
			stack[stack_len].level = 0;
		} else {
			if (stack[stack_len].indent_len < stack[stack_len - 1].indent_len) {
				stack[stack_len].level = -1;

				for (i = stack_len; i > 0; i--) {
					if (stack[stack_len].indent_len > stack[i - 1].indent_len) {
						error("Bad backwards indentation - no matching level.");
					} else if (stack[stack_len].indent_len == stack[i - 1].indent_len) {
						if (memcmp(stack[stack_len].indent, stack[i - 1].indent, stack[stack_len].indent_len)) {
							error("Bad backwards indentation - whitespace mismatch.");
						}
						stack[stack_len].level = stack[i - 1].level;
						break;
					}
				}

				if (stack[stack_len].level < 0) {
					error("Bad backwards indentation - previous level not found.");
				}
			} else {
				/* Make sure the indentation matches. */
				if (memcmp(stack[stack_len].indent, stack[stack_len - 1].indent, stack[stack_len - 1].indent_len)) {
					error("Indentation not a subset.");
				}

				stack[stack_len].level = stack[stack_len - 1].level;

				if (stack[stack_len].indent_len > stack[stack_len - 1].indent_len) {
					/* A subset of the previous. */
					if (stack[stack_len - 1].dat_len > 0) {
						error("A TLV with explicit data may not have nested elements.");
					}
					stack[stack_len].level++;
					stack[stack_len - 1].isNested = 1;
				} 

			}
		}

		/* Serialize the TLV if there level returned to 0. */
		if (stack_len != 0 && stack[stack_len].level == 0) {
			unsigned char buf[0xffff + 4];
			size_t buf_len = 0;

			buf_len = serializeStack(stack, stack_len + 1, buf, sizeof(buf));
			printf("Serialized tlv length = %llu\n", buf_len);			

			stack_len = 0;

		} else {
			stack_len++;
		}

		/* Sanity check. */
		if (stack_len >= stack_size) {
			TlvLine *tmp = NULL;
			stack_size += 100;

			tmp = realloc(stack, stack_size * sizeof(TlvLine));
			if (tmp == NULL) {
				error("Unable to reallocate internal buffer.");
			}
			stack = tmp;
		}
	}

	if (stack_len > 0) {
		unsigned char buf[0xffff + 4];
		size_t buf_len = 0;

		buf_len = serializeStack(stack, stack_len, buf, sizeof(buf));

		fwrite(buf + sizeof(buf) - buf_len, 1, buf_len, stdout);
	}
	
	fclose(f);

	if (stack != NULL) free(stack);
}
