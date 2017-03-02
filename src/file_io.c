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


 int GT_fread(GT_Encoding enc, unsigned char **raw, size_t *size, FILE *file) {
	int res = GT_UNKNOWN_ERROR;
	unsigned char *decoded = NULL;
	unsigned char *readBuf = NULL;
	size_t bufSize = 0;
	size_t read = 0;

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
			size_t decLen = GT_GetDecodedSize(enc, encoded);

			decoded = calloc(decLen, sizeof(char));
			if (decoded == NULL) {
				fprintf(stderr, "Out of memory.\n");
				goto cleanup;
			}

			switch (enc) {
				case GT_BASE_16: res = GT_Base16_decode(encoded, decoded, &decLen); break;
				case GT_BASE_64: res = GT_Base64_decode(encoded, decoded, &decLen); break;
				default:      res = GT_INVALID_ARGUMENT; break;
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
	long curPos = ftell(file);
	long endPos;
	if (fseek(file, 0L, SEEK_END)) return -1L;
	endPos = ftell(file);
	if (fseek(file, curPos, SEEK_SET)) return -1L;
	return endPos;
}
