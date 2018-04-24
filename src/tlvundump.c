#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>

#include "common.h"
#include "fast_tlv.h"
#include "hash.h"
#include "hmac.h"
#include "grep_tlv.h"

#ifdef _WIN32
#	include <io.h>
#	include <fcntl.h>
#endif

#ifdef _WIN32
#	define popen  _popen
#	define pclose _pclose
#endif

#define error_log(s, lineNr) { fprintf(stderr, "%s:%llu - %s\n", fileName, (unsigned long long)(lineNr), (s)); }
#define line_error(err, s, lineNr) { error_log(s, lineNr); return err; }
#define error(err, s) line_error(err, (s), lineNr)

/* Supported function scripts. */
#define HMAC_CALC_FUNC "HMAC"

#define HMAC_TOKEN_BUF 64
#define FUNC_SCRIPT_BUF 1024
#define HMAC_CALC_ARG_DEL "|"

size_t lineNr = 0;
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

	ST_FUNC,
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

struct HmacCalculationInfo {
	int isValid;

	char algId[HMAC_TOKEN_BUF];
	char key[HMAC_TOKEN_BUF];
	char pattern[HMAC_TOKEN_BUF];

	unsigned char ver;
	size_t stack_pos;
} hmacCalcInfo = {0};

static int serializeStack(TlvLine *stack, size_t stack_len, unsigned char *buf, size_t buf_len, size_t *total_len);
static int writeStream(const void *raw, size_t size, size_t count, FILE *f);

static int hmacGetScriptTokens(char *args, size_t aLen, char *alg, char *key, char *pat, unsigned char *ver) {
	int res = GT_PARSER_ERROR;
	char *tmp = NULL;
	char *token = NULL;

	/* Make a temporary copy of the func script for further manipulation. */
	tmp = malloc(aLen + 1);
	if (tmp == NULL) goto cleanup;
	GT_strncpy(tmp, args, aLen + 1);

	/* Break the arguments up into tokens. */

	/* Read calculation approach version. */
	token = strtok(tmp, HMAC_CALC_ARG_DEL);
	if (token == NULL) goto cleanup;
	*ver = atoi(token + 1);
	/* Verify for known version numbers. */
	if (!(*ver == 1 || *ver == 2)) goto cleanup;


	/* Read hash algorithm. */
	token = strtok(NULL, HMAC_CALC_ARG_DEL);
	if (token == NULL) goto cleanup;
	strcpy(alg, token);

	/* Read openssl key. */
	token = strtok(NULL, HMAC_CALC_ARG_DEL);
	if (token == NULL) goto cleanup;
	strcpy(key, token);

	if (*ver == 1) {
		/* Read TLV pattern to include into calculation. */
		token = strtok(NULL, HMAC_CALC_ARG_DEL);
		if (token == NULL) goto cleanup;
		strcpy(pat, token);
	}

	/* Check if there are unknown parameters. */
	token = strtok(NULL, HMAC_CALC_ARG_DEL);
	if (token != NULL) goto cleanup;

	res = GT_OK;
cleanup:
	if (tmp) free(tmp);
	return res;
}

static int initHmacCalcInfo(char *script, size_t spos) {
	int res = GT_UNKNOWN_ERROR;
	char *argBeg = strchr(script, '(') + 1;
	char *argEnd = strchr(script, ')');
	size_t argStrLen = argEnd - argBeg;

	hmacCalcInfo.isValid = 0;

	res = hmacGetScriptTokens(argBeg, argStrLen, hmacCalcInfo.algId, hmacCalcInfo.key, hmacCalcInfo.pattern, &hmacCalcInfo.ver);
	if (res != GT_OK) goto cleanup;

	hmacCalcInfo.stack_pos = spos;
	hmacCalcInfo.isValid = 1;

cleanup:
	return res;
}

static int calculateHmac(unsigned char *hmac, size_t *hlen, TlvLine *stack, size_t stack_len, int isLastTlv) {
	int res = GT_UNKNOWN_ERROR;
	unsigned char *raw = NULL;
	size_t raw_len = 0;
	size_t calc_len = 0;
	unsigned char tmp[GT_HASH_MAX_LEN];
	unsigned int tmp_len;
	GT_Hash_AlgorithmId algId;
	GT_GrepPattern *pattern = NULL;
	unsigned char *buf = NULL;

	GT_ElementCounter *idx = NULL;

	if (stack == NULL || stack_len == 0) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	raw = calloc(GT_TLV_BUF_SIZE, 1);
	if (raw == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* Verify that HMAC is PDU child in first level. */
	if (stack[hmacCalcInfo.stack_pos].level != 1) {
		res = GT_INVALID_FORMAT;
		error_log("HMAC TLV is not first level PDU child.", hmacCalcInfo.stack_pos + 1);
		goto cleanup;
	}

	/* Serialize current stack. */
	res = serializeStack(stack, stack_len, raw, GT_TLV_BUF_SIZE, &raw_len);
	if (res != GT_OK) {
		error_log("Failed to generate raw data.", hmacCalcInfo.stack_pos + 1);
		goto cleanup;
	}


	res = GT_Hash_getAlgorithmId(hmacCalcInfo.algId, &algId);
	if (res != GT_OK) {
		error_log("Failed to get hash algorithm id.", hmacCalcInfo.stack_pos + 1);
		goto cleanup;
	}

	switch (hmacCalcInfo.ver) {
		case 2:
			{
				/* HMAC in v2 approach should be last in PDU. */
				if (!isLastTlv) {
					res = GT_INVALID_FORMAT;
					error_log("HMAC TLV is not last in PDU.", hmacCalcInfo.stack_pos + 1);
					goto cleanup;
				}

				calc_len = raw_len - GT_Hash_getAlgorithmLenght(algId);

				res = GT_Hmac_Calculate(algId, hmacCalcInfo.key, strlen(hmacCalcInfo.key), raw + GT_TLV_BUF_SIZE - raw_len, calc_len, tmp, &tmp_len);
				if (res != GT_OK) goto cleanup;
			}
			break;

		case 1:
		default:
			{
				GT_GrepTlvConf conf;
				GT_FTLV t;
				unsigned char *raw_buf_ptr = raw + GT_TLV_BUF_SIZE - raw_len;

				buf = calloc(GT_TLV_BUF_SIZE, 1);
				if (buf == NULL) {
					res = GT_OUT_OF_MEMORY;
					goto cleanup;
				}

				idx = calloc(sizeof(GT_ElementCounter), 1);
				if (idx == NULL) {
					res = GT_OUT_OF_MEMORY;
					goto cleanup;
				}

				GT_GrepTlv_initConf(&conf);
				conf.print_raw = true;
				conf.print_path = false;
				conf.print_tlv_hdr = true;

				res = GT_FTLV_memRead(raw_buf_ptr, raw_len, &t);
				if (res == GT_OK && raw_len < t.hdr_len + t.dat_len) {
					res = GT_BUFFER_OVERFLOW;
				}
				if (res != GT_OK) {
					error_log("Failed to init raw TLV.", hmacCalcInfo.stack_pos + 1);
					goto cleanup;
				}

				/* Parse the pattern. */
				res = GT_GrepPattern_parse(hmacCalcInfo.pattern, &pattern);
				if (res != GT_OK) {
					error_log("Invalid pattern.", hmacCalcInfo.stack_pos + 1);
					goto cleanup;
				}

				res = GT_grepTlv(&conf, pattern, NULL, idx, raw_buf_ptr, &t, buf, &calc_len);
				if (res != GT_OK) {
					error_log("Failed to grep pattern.", hmacCalcInfo.stack_pos + 1);
					goto cleanup;
				}

				if (calc_len == 0) {
					error_log("Pattern not found.", hmacCalcInfo.stack_pos + 1);
					res = GT_INVALID_FORMAT;
					goto cleanup;
				}

				res = GT_Hmac_Calculate(algId, hmacCalcInfo.key, strlen(hmacCalcInfo.key), buf, calc_len, tmp, &tmp_len);
				if (res != GT_OK) goto cleanup;
			}
			break;
	}

	memcpy(hmac, tmp, tmp_len);
	*hlen = tmp_len;

	res = GT_OK;
cleanup:

	free(buf);
	free(idx);
	free(raw);
	GT_GrepPattern_free(pattern);

	return res;
}

int parseTlv(FILE *f, TlvLine *stack, size_t stackLen) {
	int state = ST_BEGIN;
	TlvLine *tlv = stack + stackLen;
	int c;

	memset(tlv, 0, sizeof(TlvLine));

	c = fgetc(f);
	lineNr++;
	for (;;) {
		switch(state) {
			case ST_BEGIN:
				if (IS_HEX(c)) {
					state = ST_RAW_CONTENT;
					continue;
				}
				if (c == '\n') {
					/* Count newlines. */
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
					error(GT_INVALID_FORMAT, "TLV tag value may not exceed 0x1fff.");
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
						error(GT_INVALID_FORMAT, "Unexpected flag.");
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
				} else if (c == '$') {
					state = ST_FUNC;
					continue;
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
						error(GT_INVALID_FORMAT, "String value too large.");
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
					tlv->dat[tlv->dat_len] = HEXCHAR_TO_DEC(c) << 4;
					state = ST_DATA_HEX_2;
				} else {
					state = ST_END;
					continue;
				}
				break;
			case ST_DATA_HEX_2:
				if (IS_SPACE(c)) break;
				if (IS_HEX(c)) {
					tlv->dat[tlv->dat_len++] |= HEXCHAR_TO_DEC(c);
					state = ST_DATA_HEX_1;
				} else {
						char message[256];
						if (c == EOF) GT_snprintf(message, sizeof(message), "Hex strings must contain even number of characters.");
						else if (isprint(c)) GT_snprintf(message, sizeof(message), "Hex string contains unknown character: '%c'.", c);
						else GT_snprintf(message, sizeof(message), "Hex string contains unknown character (hex value): 0x%02x.", c);
						error(GT_INVALID_FORMAT, message);
				}
				break;

			case ST_FUNC:
				{
					char funcScript[FUNC_SCRIPT_BUF];

					/* Read function script. */
					if (fgets(funcScript, sizeof(funcScript), f) != funcScript) {
						error(GT_PARSER_ERROR, "Unable to read function script.");
					}

					/* Find handler. */
					if (strstr(funcScript, HMAC_CALC_FUNC) == funcScript) {
						GT_Hash_AlgorithmId algId;
						size_t algSize;

						if (initHmacCalcInfo(funcScript, stackLen) != GT_OK) {
							error(GT_INVALID_FORMAT, "Error in HMAC function call definition.");
						}

						if (GT_Hash_getAlgorithmId(hmacCalcInfo.algId, &algId) != GT_OK) {
							error(GT_INVALID_FORMAT, "Unable to get hash algorithm id.");
						}

						if (!GT_Hmac_IsAlgorithmsSupported(algId)) {
							error(GT_INVALID_FORMAT, "Unsupported hash algorithm.");
						}

						/* Add algorithm id and init hmac hash value to 0. */
						tlv->dat[tlv->dat_len++] = algId;
						algSize = GT_Hash_getAlgorithmLenght(algId);
						memset(&tlv->dat[tlv->dat_len], 0, algSize);
						tlv->dat_len += algSize;
					} else {
						error(GT_INVALID_FORMAT, "Unknown function script.");
					}
					tlv->lineNr = lineNr;
					return GT_OK; /* Indicate success. */
				}
				break;

			case ST_END:
				if (IS_SPACE(c)) break;
				if (c == '\r') break;
				if (c == '\n' || c == EOF) {
					tlv->lineNr = lineNr;

					if (tlv->force == 8 && tlv->dat_len > 0xff) {
						error(GT_INVALID_FORMAT, "Unable to fit data into TLV8.");
					}

					return GT_OK; /* Indicate success. */
				} else {
					char buf[40];
					if (isprint(c)) {
						sprintf(buf, "Unexpected character: '%c'.", (unsigned char)c);
					} else {
						sprintf(buf, "Unexpected character (hex value): %02x.", (unsigned char)c);
					}
					error(GT_INVALID_FORMAT, buf);
				}
				break;
			default:
				error(GT_UNKNOWN_ERROR, "Unknown error.");
		}
		c = fgetc(f);
	}

	error(GT_UNKNOWN_ERROR, "Unknown format error.");
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
		/* Sanity check - double check in case it was not detected during parsing. */
		if (subLen != 0) {
			line_error(GT_INVALID_FORMAT, "A TLV with explicit data may not have nested elements.", stack[0].lineNr);
		}
		memcpy(buf + buf_len - len - stack[0].dat_len, stack[0].dat, stack[0].dat_len);
		len += subLen = stack[0].dat_len;
	}

	/* Skip the header, if the TLV is headless. */
	if (stack[0].headless) {
		res = GT_OK;
		goto cleanup;
	}

	if (stack[0].tag > GT_TLV_TYPE_1ST_BYTE_MASK || subLen > 0xff || stack[0].force == 16) {
		/* TLV16 */
		if (buf_len - len < 4) {
			line_error(GT_BUFFER_OVERFLOW, "TLV16 buffer overflow.", stack[0].lineNr);
		}

		/* Sanity check - double check in case it was not detected during parsing. */
		if (stack[0].force == 8) {
			line_error(GT_INVALID_FORMAT, "Unable to fit data into TLV8.", stack[0].lineNr);
		}
		buf[buf_len - len - 1] = subLen & 0xff;
		buf[buf_len - len - 2] = (subLen >> 8) & 0xff;
		buf[buf_len - len - 3] = stack[0].tag & 0xff;
		buf[buf_len - len - 4] = (stack[0].tag >> 8) & GT_TLV_TYPE_1ST_BYTE_MASK;
		len += 4;

		buf[buf_len - len] |= GT_TLV_MASK_TLV16;

	} else {
		if (buf_len - len < 2) {
			line_error(GT_BUFFER_OVERFLOW, "TLV8 buffer overflow.", stack[0].lineNr);
		}
		buf[buf_len - len - 1] = subLen & 0xff;
		buf[buf_len - len - 2] = stack[0].tag & GT_TLV_TYPE_1ST_BYTE_MASK;
		len += 2;
	}

	if (stack[0].isNc) buf[buf_len - len] |= GT_TLV_MASK_NON_CRITICAL;
	if (stack[0].isFw) buf[buf_len - len] |= GT_TLV_MASK_FORWARD;

	res = GT_OK;
cleanup:
	if (total_len) *total_len = len;

	return res;
}

static int writeStream(const void *raw, size_t size, size_t count, FILE *f) {
	if (f != NULL) {
		setBinaryMode(f);
	}

	if (fwrite(raw, size, count, f) != count) {
		error(GT_IO_ERROR, "Failed to write to stream.");
	}

	return GT_OK;
}

static int runPostponedTasks(TlvLine *stack, size_t stackLen) {
	int res = GT_OK;

	/* Check if HMAC calculation is on hold. */
	if (hmacCalcInfo.isValid) {
		unsigned char hmacRaw[1024] = {0};
		size_t hmacLen = 0;
		TlvLine *tlv = &stack[hmacCalcInfo.stack_pos];

		res = calculateHmac(hmacRaw, &hmacLen, stack, stackLen, ((stackLen-1) == hmacCalcInfo.stack_pos));
		if (res != GT_OK) line_error(res, "Failed to calculate HMAC.", hmacCalcInfo.stack_pos+1);
		memcpy(&tlv->dat[tlv->dat_len - hmacLen], hmacRaw, hmacLen);
		/* Invalidate info. */
		hmacCalcInfo.isValid = 0;
	}
	return res;
}

static int convertStream(FILE *f) {
	int res = GT_UNKNOWN_ERROR;
	TlvLine *stack = NULL;
	size_t stack_size = 100;
	size_t stack_len = 0;
	size_t i;
	unsigned char *buf = NULL;

	buf = calloc(GT_TLV_BUF_SIZE, 1);
	if (buf == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	stack = calloc(stack_size, sizeof(TlvLine));
	if (stack == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	while (1) {
		res = parseTlv(f, stack, stack_len);
		if (res == GT_END_OF_STREAM) {
			break;
		}
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
						res = GT_INVALID_FORMAT;
						error_log("Bad backwards indentation - no matching level.", stack[stack_len].lineNr);
						goto cleanup;
					} else if (stack[stack_len].indent_len == stack[i - 1].indent_len) {
						if (memcmp(stack[stack_len].indent, stack[i - 1].indent, stack[stack_len].indent_len)) {
							res = GT_INVALID_FORMAT;
							error_log("Bad backwards indentation - whitespace mismatch.", stack[stack_len].lineNr);
							goto cleanup;
						}
						stack[stack_len].level = stack[i - 1].level;
						break;
					}
				}

				if (stack[stack_len].level < 0) {
					res = GT_INVALID_FORMAT;
					error_log("Bad backwards indentation - previous level not found.", stack[stack_len].lineNr);
					goto cleanup;
				}
			} else {
				/* Make sure the indentation matches. */
				if (memcmp(stack[stack_len].indent, stack[stack_len - 1].indent, stack[stack_len - 1].indent_len)) {
					res = GT_INVALID_FORMAT;
					error_log("Indentation not a subset.", stack[stack_len].lineNr);
					goto cleanup;
				}

				stack[stack_len].level = stack[stack_len - 1].level;

				if (stack[stack_len].indent_len > stack[stack_len - 1].indent_len) {
					/* A subset of the previous. */
					if (stack[stack_len - 1].dat_len > 0) {
						res = GT_INVALID_FORMAT;
						error_log("A TLV with explicit data may not have nested elements.", stack[stack_len].lineNr);
						goto cleanup;
					}
					stack[stack_len].level++;
				}

			}
		}

		/* Serialize the TLV if there level returned to 0. */
		if (stack_len != 0 && stack[stack_len].level == 0) {
			size_t buf_len = 0;

			res = runPostponedTasks(stack, stack_len);
			if (res != GT_OK) goto cleanup;

			res = serializeStack(stack, stack_len, buf, GT_TLV_BUF_SIZE, &buf_len);
			if (res != GT_OK) goto cleanup;

			res = writeStream(buf + GT_TLV_BUF_SIZE - buf_len, 1, buf_len, stdout);
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
				res = GT_OUT_OF_MEMORY;
				error_log("Unable to reallocate internal buffer.", stack[stack_len].lineNr);
				goto cleanup;
			}
			stack = tmp;
		}
	}

	if (stack_len > 0) {
		size_t buf_len = 0;

		res = runPostponedTasks(stack, stack_len);
		if (res != GT_OK) goto cleanup;

		res = serializeStack(stack, stack_len, buf, GT_TLV_BUF_SIZE, &buf_len);
		if (res != GT_OK) goto cleanup;

		res = writeStream(buf + GT_TLV_BUF_SIZE - buf_len, 1, buf_len, stdout);
		if (res != GT_OK) goto cleanup;
	}

	res = GT_OK;

cleanup:

	free(buf);
	free(stack);

	return res;
}

int getListOfSupportedHashAlgs(char *buf, size_t bufLen) {
	int res = GT_UNKNOWN_ERROR;
	size_t len = 1;
	int i;

	if (bufLen < len) {
		res = GT_BUFFER_OVERFLOW;
		goto cleanup;
	}
	buf[0] = '\0';

	for (i = 0; i < GT_NOF_HASHALGS; i++) {

		if (GT_Hmac_IsAlgorithmsSupported(i)) {
			const char *name = NULL;
			name = GT_Hash_getAlgorithmName(i);
			len += strlen(name) + 1;
			if (len > bufLen) {
				res = GT_BUFFER_OVERFLOW;
				goto cleanup;
			}
			strcat(buf, name);
			strcat(buf, " ");
		}
	}

	res = GT_OK;
cleanup:
	return res;
}

int main(int argc, char **argv) {
	int res = GT_UNKNOWN_ERROR;
	FILE *f = NULL;
	int c;

	while ((c = getopt(argc, argv, "hv")) != -1) {
		switch(c) {
			case 'h':
				{
					char buf[1024];

					res = getListOfSupportedHashAlgs(buf, sizeof(buf));
					if (res != GT_OK) goto cleanup;

					printf("Usage:\n"
							"  gttlvundump [-h] [-v] [file...]\n"
							"\n"
							"Options:\n"
							"    -h       This help message.\n"
							"    -v       TLV utility package version.\n"
							"\n"
							"\n"
							"Functions:\n"
							"  HMAC(version|algorithm|key|pattern)\n"
							"    version:\n"
							"            v1 - computation is performed for each TLV element over the\n"
							"                 concatenation of their header and value.\n"
							"            v2 - computation is performed for the whole set of TLV elements\n"
							"                 over the TLV set header, each TLV element header and value\n"
							"                 in the order in which they appear within the TLV file, and\n"
							"                 the header and the hash function ID of the MAC element itself.\n"
							"    algorithm:\n"
							"            Hash algorithm to be used for computation. See section Supported\n"
							"            hash algorithms below.\n"
							"    key:    Secret cryptographic key for computing HMAC.\n"
							"    pattern:\n"
							"            TLV pattern describing TLVs to be included into computation\n"
							"            (valid with v1). Pattern format as defined by gttlvgrep.\n"
							"\n"
							"\n"
							"Example:\n"
							"  1. PDU v1 HMAC calculation.\n"
							"    TLV[0300]:\n"
							"      TLV[01]:\n"
							"        TLV[01]:616E6F6E00\n"
							"      TLV[0301]:\n"
							"        TLV[01]:01\n"
							"        TLV[02]:54D9D6E7\n"
							"        TLV[03]:54D9D6E7\n"
							"      TLV[1f]:$HMAC(v1|sha256|anon|300.01,301)\n"
							"  2. PDU v2 HMAC calculation.\n"
							"    TLV[0300]:\n"
							"      TLV[01]:\n"
							"        TLV[01]:616E6F6E00\n"
							"      TLV[0301]:\n"
							"        TLV[01]:01\n"
							"        TLV[02]:54D9D6E7\n"
							"        TLV[03]:54D9D6E7\n"
							"      TLV[1f]:$HMAC(v2|sha256|anon)\n"
							"\n"
							"Cryptogrophy provider:\n"
							"  %s\n"
							"\n"
							"Supported hash algorithms:\n"
							"  %s\n"
							"\n",
							GT_Hmac_GetCryptoProvider(),
							buf
							);
					res = GT_OK;
					goto cleanup;
				}
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

	res = GT_OK;
cleanup:
	if (f != NULL && f != stdin) fclose(f);

	return tlvutil_ErrToExitcode(res);
}

