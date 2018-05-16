/*
 * Copyright 2013-2017 Guardtime, Inc.
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

#include "common.h"
#include <stdio.h>
#include <stdarg.h>

int print_error(const char *format, ...) {
	int ret;
	va_list va;

	fflush(stdout);

	va_start(va, format);
	ret = vfprintf(stderr, format, va);
	va_end(va);
	return ret;
}

int tlvutil_ErrToExitcode(int error_code) {
	switch (error_code) {
		case GT_OK:
			return EXIT_SUCCESS;
		case GT_BUFFER_OVERFLOW:
		case GT_UNKNOWN_ERROR:
		case GT_INVALID_ARGUMENT:
			return EXIT_FAILURE;
		case GT_INVALID_CMD_PARAM:
			return EXIT_INVALID_CL_PARAMETERS;
		case GT_IO_ERROR:
			return EXIT_IO_ERROR;
		case GT_INVALID_FORMAT:
		case GT_PARSER_ERROR:
		case GT_DUPLICATE_ERROR:
		case GT_END_OF_STREAM:
			return EXIT_INVALID_FORMAT;
		case GT_CRYPTO_FAILURE:
			return EXIT_CRYPTO_ERROR;
		case GT_OUT_OF_MEMORY:
			return EXIT_OUT_OF_MEMORY;
		default:
			return EXIT_FAILURE;
	}
}
