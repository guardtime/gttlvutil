#ifndef COMMON_H_
#define COMMON_H_

#include <stdlib.h>
#include <ctype.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#	ifndef snprintf
#		define snprintf _snprintf
#	endif
#endif

#define GT_TLV_MASK_TLV16 0x80u
#define GT_TLV_MASK_NON_CRITICAL 0x40u
#define GT_TLV_MASK_FORWARD 0x20u

#define GT_TLV_MASK_TLV8_TYPE 0x1fu

#define TLV_UTIL_VERSION_STRING (PACKAGE_NAME" "VERSION)

#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')
#define IS_DIGIT(c) ((c) >= '0' && (c) <= '9')
#define IS_HEX(c) (IS_DIGIT(c) || (toupper(c) >= 'A' && toupper(c) <= 'F'))
#define DECCHAR_TO_DEC(c) ((c) - '0')
#define HEXCHAR_TO_DEC(c) (IS_DIGIT(c) ? DECCHAR_TO_DEC(c) : (toupper((c)) - 'A' + 10))

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


typedef enum {
	false = 0, true = !false
} bool;

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

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H_ */


