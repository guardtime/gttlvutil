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



static const char base64EncodeTable[65] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

static const char base32EncodeTable[33] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"234567";

static void initDecodeTable(unsigned char *decTbl, const char *encTbl, size_t encLen) {
	unsigned char i;
	for (i = 0; i < encLen; i++) {
		decTbl[(unsigned char)encTbl[i]] = i;
	}
}

int GT_Base64_decode(const char *encoded, unsigned char **data, size_t *data_len) {
	int res = GT_UNKNOWN_ERROR;
	size_t r = 0;
	size_t gc = 0;
	unsigned char *tmp = NULL;
	size_t inLen;
	size_t outLen = 0;
	const char *padding = NULL;
	const char *p = NULL;
	unsigned char alphabet[0xff] = {0};

	if (encoded == NULL || data == NULL || data_len == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	p = encoded;
	while (*p) {
		if (IS_GROUPING_CHAR(*p) || IS_SPACE(*p) || IS_EOL(*p)) gc++;
		p++;
	}

	inLen = strlen(encoded);

	/* Check if base64 string has a specified length. */
	if ((inLen - gc) % 4 != 0) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	padding = strchr(encoded, PADDING_CHAR);
	if (padding != NULL) {
		size_t padSize = inLen - (padding - encoded);
		/* Padding can be only on last two chars. */
		if (padSize > 2) {
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}
		inLen -= padSize;
	}

	outLen = 3 * (inLen - gc) / 4;

	tmp = calloc(outLen, sizeof(unsigned char));
	if (tmp == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

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
			} else if (IS_GROUPING_CHAR(*p) || IS_SPACE(*p) || IS_EOL(*p)) {
				p++;
			} else {
				/* Unknown character has occured. */
				res = GT_INVALID_FORMAT;
				goto cleanup;
			}
		}
		if (count) {
			for (j = 2; j >= 0 && r < outLen; j--) {
				tmp[r++] = (block >> 8 * j) & 0xff;
			}
		}
	} while (r < outLen && *p);

	*data_len = r;
	*data = tmp;
	tmp = NULL;

	res = GT_OK;
cleanup:
	free(tmp);
	return res;
}

int GT_Base64_encode(const unsigned char *data, const size_t data_len, char **encoded) {
	int res = GT_UNKNOWN_ERROR;
	char *tmp = NULL;
	size_t outLen = 0;
	size_t r = 0;
	size_t i = 0;
	size_t padding = 0;

	if (data == NULL || data_len == 0 || encoded == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Calculate output string length. */
	outLen = (4 * ((data_len + 2) / 3)) + 1;
	/* Calculate nof padding bytes. */
	padding = (data_len % 3) ? 3 - (data_len % 3) : 0;

	tmp = calloc(outLen, sizeof(char));
	if (tmp == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	while (i < data_len) {
		int j;
		unsigned long block = 0;

		block  = (i < data_len) ? data[i++] << 2 * 8 : 0;
		block |= (i < data_len) ? data[i++] << 1 * 8 : 0;
		block |= (i < data_len) ? data[i++] << 0 * 8 : 0;

		for (j = 3; j >= 0 && r < (outLen - 1 - padding); j--) {
			tmp[r++] = base64EncodeTable[(block >> 6 * j) & 0x3f];
		}
	}

	/* Add padding bytes. */
	while (r % 4 != 0) {
		/* Should never occure, just to be sure check anyway. */
		if (r > outLen) {
			res = GT_BUFFER_OVERFLOW;
			goto cleanup;
		}
		tmp[r++] = PADDING_CHAR;
	}

	tmp[r++] = '\0';
	*encoded = tmp;
	tmp = NULL;

	res = GT_OK;
cleanup:
	free(tmp);
	return res;
}

int GT_Base16_decode(const char *encoded, unsigned char **data, size_t *data_len) {
	int res = GT_UNKNOWN_ERROR;
	const char *p = NULL;
	size_t gc = 0;
	size_t inLen;
	size_t outLen = 0;
	unsigned char *tmp = NULL;
	size_t i = 0;

	if (encoded == NULL || data == NULL || data_len == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	p = encoded;
	while (*p) {
		if (IS_GROUPING_CHAR(*p) || IS_SPACE(*p) || IS_EOL(*p)) gc++;
		p++;
	}

	inLen = strlen(encoded);

	/* Check if encoded string has a specified length. */
	if ((inLen - gc) % 2 != 0) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	/* Calculate output buffer size. */
	outLen = (inLen - gc) / 2;

	tmp = calloc(outLen, sizeof(unsigned char));
	if (tmp == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	p = encoded;
	while (i < outLen) {
		int highNibble = true;
		while (*p) {
			if (IS_HEX(*p)) {
				if (highNibble) {
					tmp[i] = HEXCHAR_TO_DEC(*p) << 4;
					highNibble = false;
					p++;
				} else {
					tmp[i] |= HEXCHAR_TO_DEC(*p);
					p++;
					break;
				}
			} else if (IS_GROUPING_CHAR(*p) || IS_SPACE(*p) || IS_EOL(*p)) {
				p++;
			} else {
				/* Unknown character has occured. */
				res = GT_INVALID_FORMAT;
				goto cleanup;
			}
		}
		i++;
	}

	*data_len = i;
	*data = tmp;
	tmp = NULL;

	res = GT_OK;
cleanup:
	free(tmp);
	return res;
}

int GT_Base16_encode(const unsigned char *data, const size_t data_len, char **encoded) {
	int res = GT_UNKNOWN_ERROR;
#if 0
	char *tmp = NULL;
	size_t outLen = 0;
	size_t r = 0;
	size_t i = 0;
	size_t padding = 0;

	if (data == NULL || data_len == 0 || encoded == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Calculate output string length. */
	outLen = (4 * ((data_len + 2) / 3)) + 1;
	/* Calculate nof padding bytes. */
	padding = (data_len % 3) ? 3 - (data_len % 3) : 0;

	tmp = calloc(outLen, sizeof(char));
	if (tmp == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	while (i < data_len) {
		int j;
		unsigned long block = 0;

		block  = (i < data_len) ? data[i++] << 2 * 8 : 0;
		block |= (i < data_len) ? data[i++] << 1 * 8 : 0;
		block |= (i < data_len) ? data[i++] << 0 * 8 : 0;

		for (j = 3; j >= 0 && r < (outLen - 1 - padding); j--) {
			tmp[r++] = base64EncodeTable[(block >> 6 * j) & 0x3f];
		}
	}

	/* Add padding bytes. */
	while (r % 4 != 0) {
		/* Should never occure, just to be sure check anyway. */
		if (r > outLen) {
			res = GT_BUFFER_OVERFLOW;
			goto cleanup;
		}
		tmp[r++] = PADDING_CHAR;
	}

	tmp[r++] = '\0';
	*encoded = tmp;
	tmp = NULL;

	res = GT_OK;
cleanup:
	free(tmp);
#endif
	return res;
}

typedef struct {
	const char *alias;
	GT_Encoding enc;
} encoding_map;

static const encoding_map enc_map[] = {
	{ "hex",	GT_BASE_16 },
	{ "base16",	GT_BASE_16 },
	{ "16",		GT_BASE_16 },
	{ "base64", GT_BASE_64 },
	{ "64",		GT_BASE_64 },
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
