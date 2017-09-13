/**
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

#include "file_io.h"

#include <string.h>

static unsigned char buffer[0xffff + 4];

/* Length of the data in buffer. */
static size_t buffer_len = 0;

static void shift_buffer(size_t consumed) {
	if (consumed > 0) {
		buffer_len -= consumed;
		memmove(buffer, buffer + consumed, buffer_len);
	}
}

long GT_consume_raw(unsigned char **buf, size_t consumed, FILE *file) {
	if  (buf == NULL || consumed > buffer_len || file == NULL) {
		return -1;
	}

	shift_buffer(consumed);

	if (buffer_len < sizeof(buffer) && !feof(file)) {
		buffer_len += fread(buffer + buffer_len, 1, sizeof(buffer) - buffer_len, file);
	}

	*buf = buffer;
	return buffer_len;
}

long GT_consume_hex(unsigned char **buf, size_t consumed, FILE *file) {
	size_t i;
	bool init = true;

	if  (buf == NULL || consumed > buffer_len || file == NULL) {
		return -1;
	}

	shift_buffer(consumed);

	if (buffer_len < sizeof(buffer)) {
		buffer[buffer_len] = 0;
	}

	while (buffer_len < sizeof(buffer) && !feof(file)) {
		int c = fgetc(file);
		if (c == EOF) break;

		if (c >= '0' && c <= '9') {
			if (init) {
				++buffer_len;
				buffer[buffer_len - 1] = 0;
			}
			init = !init;

			buffer[buffer_len - 1] = (buffer[buffer_len - 1] << 4) | (c - '0');

		} else if (tolower(c) >= 'a' && tolower(c <= 'f')) {
			if (init) {
				++buffer_len;
				buffer[buffer_len - 1] = 0;
			}
			init = !init;

			buffer[buffer_len - 1] = (buffer[buffer_len - 1] << 4) | (10 + (tolower(c) - 'a'));
		} else if (!isspace(c)) {
			fprintf(stderr, "Invalid hex character '%c'.\n", c);
			return -1;
		}

	}

	*buf = buffer;
	return buffer_len;
}

signed char b64map[0xff] = {
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
		-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
		-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

long GT_consume_b64(unsigned char **buf, size_t consumed, FILE *file) {
	static int state = 0;
	static char last = 0;
	char current;
	if  (buf == NULL || consumed > buffer_len || file == NULL) {
		return -1;
	}

	shift_buffer(consumed);

	while (buffer_len < sizeof(buffer) && !feof(file)) {
		int c = fgetc(file);
		if (c == EOF) break;

		if (isspace(c)) continue;

		if (c == '=') {
			switch(state) {
				case 0:
				case 1:
					fprintf(stderr, "Invalid base64 format: unexpected '=' character.\n");
					return -1;
			}
		} else {
			current = b64map[c];
			if (current < 0) {
				fprintf(stderr, "Invalid base64 format; unexpected character '%c'\n", c);
				return -1;
			}

			switch(state) {
				case 0:
					last = (current << 2) & 0xff;
					break;
				case 1:
					buffer[buffer_len++] = last | (current >> 4);
					last = (current << 4) & 0xff;
					break;
				case 2:
					buffer[buffer_len++] = last | (current >> 2);
					last = (current << 6 ) & 0xff;
					break;
				case 3:
					buffer[buffer_len++] = last | (current & 0x3f);
					break;
			}
			state = (state + 1) % 4;
		}
	}
	*buf = buffer;
	return buffer_len;
}

int GT_fread(GT_Encoding enc, unsigned char **raw, size_t *size, FILE *file) {
	int res = GT_UNKNOWN_ERROR;
	unsigned char *decoded = NULL;
	unsigned char *readBuf = NULL;
	size_t bufSize = 1; /* Extra byte for string termination. */
	size_t read = 0;

	if (raw == NULL || size == NULL || file == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	while (!feof(file)) {
		unsigned char *tmp = NULL;

		bufSize += GT_TLV_BUF_SIZE;
		tmp = realloc(readBuf, bufSize);
		if (tmp == NULL) {
			fprintf(stderr, "Out of memory.\n");
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}
		readBuf = tmp;

		read += fread(readBuf + read, 1, bufSize - read, file);

		if (ferror(file)) {
			fprintf(stderr, "Failed to read input stream.\n");
			res = GT_IO_ERROR;
			goto cleanup;
		}
	}

	if (read) {
		if (enc == GT_BASE_2) {
			*raw = readBuf;
			readBuf = NULL;
			*size = read;
		} else {
			char *encoded = (char *)readBuf;
			size_t decLen = 0;

			encoded[read] = '\0';

			decLen = GT_GetDecodedSize(enc, encoded);
			decoded = calloc(decLen, sizeof(char));
			if (decoded == NULL) {
				fprintf(stderr, "Out of memory.\n");
				goto cleanup;
			}

			switch (enc) {
				case GT_BASE_16:	res = GT_Base16_decode(encoded, decoded, &decLen); break;
				case GT_BASE_64:	res = GT_Base64_decode(encoded, decoded, &decLen); break;
				default:			res = GT_INVALID_ARGUMENT; break;
			}
			if (res != GT_OK) {
				fprintf(stderr, "Unable to decode string.\n");
				goto cleanup;
			}

			*raw = decoded;
			decoded = NULL;
			*size = decLen;
		}
	}

	res = GT_OK;
cleanup:
	free(readBuf);
	free(decoded);

	return res;
}

long GT_fsize(FILE *file) {
	long curPos;
	long endPos;

	if (file == NULL) return -1L;

	curPos = ftell(file);
	if (fseek(file, 0L, SEEK_END)) return -1L;
	endPos = ftell(file);
	if (fseek(file, curPos, SEEK_SET)) return -1L;
	return endPos;
}
