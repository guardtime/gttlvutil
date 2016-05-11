#ifndef COMMON_H_
#define COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#	ifndef snprintf
#		define snprintf _snprintf
#	endif
#endif

#define GT_TLV_MASK_TLV16 0x80u
#define GT_TLV_MASK_LENIENT 0x40u
#define GT_TLV_MASK_FORWARD 0x20u

#define GT_TLV_MASK_TLV8_TYPE 0x1fu

#define TLV_UTIL_VERSION_STRING (PACKAGE_NAME" "VERSION)

typedef enum {
	false = 0, true = !false
} bool;

enum StatusCodes {
	GT_OK,
	GT_OUT_OF_MEMORY,
	GT_FORMAT_ERROR,
	GT_IO_ERROR,
	GT_INVALID_ARGUMENT,
	GT_INVALID_FORMAT,
	GT_BUFFER_OVERFLOW,
	GT_UNKNOWN_ERROR = 0xffff
};

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H_ */


