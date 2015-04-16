#ifndef TLVDUMP_H_
#define TLVDUMP_H_

#define KSI_TLV_MASK_TLV16 0x80u
#define KSI_TLV_MASK_LENIENT 0x40u
#define KSI_TLV_MASK_FORWARD 0x20u

#define KSI_TLV_MASK_TLV8_TYPE 0x1fu

typedef enum {
	false = 0, true = !false
} bool;

enum {
	KSI_OK,
	KSI_INVALID_ARGUMENT,
	KSI_INVALID_FORMAT,
	KSI_OUT_OF_MEMORY,
	KSI_UNKNOWN_ERROR,
	KSI_IO_ERROR,
	KSI_BUFFER_OVERFLOW,
};

#endif

