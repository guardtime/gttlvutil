/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

#include "encoding.h"

#include <string.h>

#define IS_KNOWN_REDUNDANT_CHAR(c) (IS_GROUPING_CHAR(c) || IS_SPACE(c) || IS_EOL(c))

static const char base64EncodeTable[64 + 1] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

static void initDecodeTable(unsigned char *decTbl, const char *encTbl, size_t encLen) {
	unsigned char i;
	for (i = 0; i < encLen; i++) {
		decTbl[(unsigned char)encTbl[i]] = i;
	}
}

int GT_Base64_decode(const char *encoded, unsigned char *raw, size_t *raw_len) {
	int res = GT_UNKNOWN_ERROR;
	size_t r = 0;
	size_t gc = 0;
	size_t pc = 0;
	size_t inLen;
	size_t outLen = 0;
	const char *p = NULL;
	unsigned char alphabet[0xff] = {0};

	if (encoded == NULL || raw_len == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	p = encoded;
	while (*p) {
		if (IS_KNOWN_REDUNDANT_CHAR(*p)) gc++;
		else if (IS_PADDING_CHAR(*p)) pc++;
		else if (!IS_BASE64(*p)) {
			res = GT_PARSER_ERROR;
			goto cleanup;
		}
		p++;
	}

	inLen = strlen(encoded);

	/* Check if base64 string has a specified length. */
	if ((inLen - gc) % 4 != 0) {
		res = GT_PARSER_ERROR;
		goto cleanup;
	}

	outLen = 3 * (inLen - pc - gc) / 4;

	if (raw != NULL) {
		initDecodeTable(alphabet, base64EncodeTable, 64);

		p = encoded;
		do {
			int j;
			unsigned long block = 0;
			unsigned char count = 0;

			while (*p) {
				if (IS_BASE64(*p)) {
					block <<= 6;
					block |= alphabet[(unsigned char)*p];
					p++;
					if (++count == 4) break;
				} else if (IS_KNOWN_REDUNDANT_CHAR(*p)) {
					p++;
				} else {
					/* Unknown character has occured. */
					res = GT_PARSER_ERROR;
					goto cleanup;
				}
			}
			if (count) {
				for (j = 2; j >= 0 && r < outLen; j--) {
					raw[r++] = (block >> 8 * j) & 0xff;
				}
			}
		} while (r < outLen && *p);

		if (r != outLen) {
			res = GT_PARSER_ERROR;
			goto cleanup;
		}
	}

	*raw_len = outLen;

	res = GT_OK;
cleanup:
	return res;
}

int GT_Base16_decode(const char *encoded, unsigned char *raw, size_t *raw_len) {
	int res = GT_UNKNOWN_ERROR;
	const char *p = NULL;
	size_t gc = 0;
	size_t inLen;
	size_t outLen = 0;
	size_t i = 0;

	if (encoded == NULL || raw_len == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	p = encoded;
	while (*p) {
		if (IS_KNOWN_REDUNDANT_CHAR(*p)) gc++;
		else if (!IS_HEX(*p)) {
			res = GT_PARSER_ERROR;
			goto cleanup;
		}
		p++;
	}

	inLen = strlen(encoded);

	/* Check if encoded string has a specified length. */
	if ((inLen - gc) % 2 != 0) {
		res = GT_PARSER_ERROR;
		goto cleanup;
	}

	/* Calculate output buffer size. */
	outLen = (inLen - gc) / 2;

	if (raw != NULL) {
		p = encoded;
		while (i < outLen) {
			int highNibble = true;
			while (*p) {
				if (IS_HEX(*p)) {
					if (highNibble) {
						raw[i] = HEXCHAR_TO_DEC(*p) << 4;
						highNibble = false;
						p++;
					} else {
						raw[i] |= HEXCHAR_TO_DEC(*p);
						p++;
						break;
					}
				} else if (IS_KNOWN_REDUNDANT_CHAR(*p)) {
					p++;
				} else {
					/* Unknown character has occured. */
					res = GT_PARSER_ERROR;
					goto cleanup;
				}
			}
			i++;
		}

		if (i != outLen) {
			res = GT_PARSER_ERROR;
			goto cleanup;
		}
	}

	*raw_len = outLen;

	res = GT_OK;
cleanup:
	return res;
}

size_t GT_GetDecodedSize(GT_Encoding enc, const char *encoded) {
	int res;
	size_t size;

	switch (enc) {
		case GT_BASE_64:	res = GT_Base64_decode(encoded, NULL, &size); break;
		case GT_BASE_16:	res = GT_Base16_decode(encoded, NULL, &size); break;
		default:			res = GT_INVALID_ARGUMENT; break;
	}
	if (res != GT_OK) {
		size = 0;
	}
	return size;
}

typedef struct {
	const char *alias;
	GT_Encoding enc;
} encoding_map;

static const encoding_map enc_map[] = {
	{ "2",		GT_BASE_2  },
	{ "bin",	GT_BASE_2  },
	{ "raw",	GT_BASE_2  },
	{ "16",		GT_BASE_16 },
	{ "hex",	GT_BASE_16 },
	{ "base16",	GT_BASE_16 },
	{ "64",		GT_BASE_64 },
	{ "base64", GT_BASE_64 },
	{ "b64",	GT_BASE_64 },
	{ NULL,     GT_BASE_NA }
};

GT_Encoding GT_ParseEncoding(const char *enc) {
	const encoding_map *map = enc_map;

	while (map->alias != NULL) {
		if (!strcmp(map->alias, enc)) {
			return map->enc;
		}
		map++;
	}
	return GT_BASE_NA;
}
