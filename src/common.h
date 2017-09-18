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

#ifndef COMMON_H_
#define COMMON_H_

#include <stddef.h>
#include <stdlib.h>
#include <ctype.h>
#include <stddef.h>
#include "compatibility.h"

#define GT_TLV_MASK_TLV16 0x80u
#define GT_TLV_MASK_NON_CRITICAL 0x40u
#define GT_TLV_MASK_FORWARD 0x20u

#define GT_TLV_TYPE_1ST_BYTE_MASK 0x1fu

#define TLV_UTIL_VERSION_STRING (PACKAGE_NAME" "VERSION)

#define IS_EOL(c) ((c) == '\n' || (c) == '\r')
#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')
#define IS_DIGIT(c) ((c) >= '0' && (c) <= '9')
#define IS_CHAR(c) ((toupper(c) >= 'A' && toupper(c) <= 'Z'))
#define IS_HEX(c) (IS_DIGIT(c) || (toupper(c) >= 'A' && toupper(c) <= 'F'))
#define DECCHAR_TO_DEC(c) ((c) - '0')
#define HEXCHAR_TO_DEC(c) (IS_DIGIT(c) ? DECCHAR_TO_DEC(c) : (toupper((c)) - 'A' + 10))

#define GROUPING_CHAR '-'
#define PADDING_CHAR  '='
#define IS_GROUPING_CHAR(c) ((c) == GROUPING_CHAR)
#define IS_PADDING_CHAR(c)  ((c) == PADDING_CHAR)

#define IS_BASE64(c) (IS_CHAR(c) || IS_DIGIT(c) || (c) == '+' || (c) == '/' || IS_PADDING_CHAR(c))


/**
 * Crypto implementations.
 */
#define HASH_OPENSSL   1
#define HASH_CRYPTOAPI 2

/**
* Default implementation for data hashing.
*/
#ifndef CRYPTO_IMPL
#	define CRYPTO_IMPL HASH_OPENSSL
#endif

#define GT_TLV_BUF_SIZE (0xffff + 4)

#ifdef _WIN32
#  define setBinaryMode(f) _setmode(_fileno(f), _O_BINARY);
#else
#  define setBinaryMode(f)
#endif

typedef enum {
	false = 0, true = !false
} bool;

/**
 * Flushes stdout and prints the message to stderr stream.
 */
int print_error(const char *fmt, ...);

enum StatusCodes {
	GT_OK = 0,
	GT_INVALID_CMD_PARAM,
	GT_OUT_OF_MEMORY,
	GT_FORMAT_ERROR,
	GT_IO_ERROR,
	GT_INVALID_ARGUMENT,
	GT_INVALID_FORMAT,
	GT_BUFFER_OVERFLOW,
	GT_PARSER_ERROR,
	GT_CRYPTO_FAILURE,
	GT_DUPLICATE_ERROR,

	GT_END_OF_STREAM,
	GT_UNKNOWN_ERROR = 0xffff
};

#endif /* COMMON_H_ */


