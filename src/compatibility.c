/*
 * Copyright 2013-2015 Guardtime, Inc.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "compatibility.h"
#include "common.h"


#ifdef _WIN32
size_t GT_vsnprintf(char *buf, size_t n, const char *format, va_list va){
	size_t ret = 0;
	int tmp;
	if (buf == NULL || n > INT_MAX || n == 0 || format == NULL) goto cleanup;
	/* NOTE: If there is empty space in buf, it will be filled with 0x00 or 0xfe. */
	tmp = vsnprintf_s(buf, n, _TRUNCATE, format, va);
	if (tmp < 0) {
		ret = n - 1;
		goto cleanup;
	}
	ret = (size_t) tmp;

cleanup:

	return ret;
}
#else
size_t GT_vsnprintf(char *buf, size_t n, const char *format, va_list va){
	size_t ret = 0;
	if (buf == NULL || n > INT_MAX || n == 0 || format == NULL) goto cleanup;
	ret = vsnprintf(buf, n, format, va);
	if (ret >= n) {
		ret = n - 1;
		goto cleanup;
	}

cleanup:

	return ret;
}
#endif

size_t GT_snprintf(char *buf, size_t n, const char *format, ... ){
	size_t ret;
	va_list va;
	va_start(va, format);
	ret = GT_vsnprintf(buf, n, format, va);
	va_end(va);
	return ret;
}

char *GT_strncpy (char *destination, const char *source, size_t n){
	char *ret = NULL;
	if (destination == NULL || source == NULL || n == 0) {
		goto cleanup;
	}
	ret = strncpy(destination, source, n - 1);
	destination[n - 1] = 0;

cleanup:

	return ret;
}

int GT_strdup(const char *from, char **to) {
	int res = GT_UNKNOWN_ERROR;
	size_t len;
	char *tmp = NULL;

	if (from == NULL || to == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	len = strlen(from) + 1;

	tmp = malloc(len);
	if (tmp == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	GT_strncpy(tmp, from, len);

	*to = tmp;
	tmp = NULL;

	res = GT_OK;

cleanup:

	free(tmp);

	return res;
}
