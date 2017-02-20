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



static size_t calculateEncBufLen(GT_Encoding enc, size_t bufSize) {
	switch (enc) {
		case GT_BASE_64:	return (4 * ((bufSize + 2) / 3)) + 1;
		case GT_BASE_16:	return bufSize * 2;
		default:		return bufSize;
	}
}

size_t GT_fread(GT_Encoding enc, void * dstBuf,  size_t elementSize, size_t count, FILE *file) {
	size_t dstLen = 0;
	char *encoded = NULL;
	unsigned char *decoded = NULL;
	size_t decLen = 0;

	if (enc == GT_BASE_2) {
		dstLen = fread(dstBuf, elementSize, count, file);
	} else {
		int res;
		size_t read = 0;
		size_t encBufSize = calculateEncBufLen(enc, count);

		if ((encoded = calloc(encBufSize, sizeof(char))) == NULL) {
			fprintf(stderr, "Out of memory.\n");
			goto cleanup;
		}

		read = fread(encoded, sizeof(char), encBufSize, file);
		if (read != strlen(encoded)) {
			fprintf(stderr, "Inconsistent file read buffer.\n");
			goto cleanup;
		}

		if (read) {
			switch (enc) {
				case GT_BASE_64: res = GT_Base64_decode(encoded, &decoded, &decLen); break;
				case GT_BASE_16: res = GT_Base16_decode(encoded, &decoded, &decLen); break;
				default:      res = GT_INVALID_ARGUMENT; break;
			}
			if (res != GT_OK) {
				fprintf(stderr, "Unable to decode string.\n");
				goto cleanup;
			}

			if (decLen > count) {
				fprintf(stderr, "Decoded data buffer overflow.\n");
				goto cleanup;
			}
			memcpy(dstBuf, decoded, decLen);
			dstLen = decLen;
		}
	}
cleanup:
	free(encoded);
	free(decoded);

	return dstLen;
}

long GT_fsize(FILE *file) {
	long curPos = ftell(file);
	long endPos;
	if (fseek(file, 0L, SEEK_END)) return -1L;
	endPos = ftell(file);
	if (fseek(file, curPos, SEEK_SET)) return -1L;
	return endPos;
}
