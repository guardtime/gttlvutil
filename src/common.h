#ifndef COMMON_H_
#define COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

enum StatusCodes {
	GT_OK,
	GT_OUT_OF_MEMORY,
	GT_FORMAT_ERROR,
	GT_IO_ERROR,
	GT_INVALID_ARGUMENT,
	GT_UNKNOWN_ERROR = 0xffff
};

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H_ */
