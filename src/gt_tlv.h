#ifndef GT_TLV_H_INCLUDED
#define GT_TLV_H_INCLUDED

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Determine the TLV size - TLV8 or TLV16 */
#define GT_is_tlv_flag_tlv16(tlv) (*(tlv)->header & 0x80)
/* If the TLV is unknown and lenient - should the value be forwarded after processing. */
#define GT_is_tlv_flag_forward(tlv) (*(tlv)->header & 0x40)
/* If the TLV is unknown but lenient then no error is produced */
#define GT_is_tlv_flag_lenient(tlv) ((*(tlv)->header & 0x20))

/*
 * Basic representation of a TLV. The payload itself may contain one or more TLVs.
 */
typedef struct GTTlv_st GTTlv;
/*
 * The TLVs may be read from a file or memory.
 */
typedef struct GTTlvReader_st GTTlvReader;

struct GTTlv_st {
	/* Header, may be 2 or 4 bytes long. */
	uint8_t header[4];
	/* Length of the header. */
	size_t header_len;
	/* TLV type. */
	uint16_t type;
	/* Length of the raw data. */
	size_t payload_length;
	/* Raw data, may contain other TLV. */
	uint8_t *payload;
	/* Relative offset of the current TLV. */
	size_t relativeOffset;
	/* Next TLV; Used to hold sequence of TLVs */
	GTTlv *next;
};

struct GTTlvReader_st {
	/* The TLV is read from stream */
	FILE *file;
	/* If file is NULL, the TLV is read from memory.
	 * NB! This is not a local copy of the actual data. */
	const uint8_t *data;
	/* Length of data in memory */
	size_t data_len;
	/* Relative offset */
	size_t relativeOffset;
};

/*
 * Create a reader for reading from an open file.
 */
int GTTlvTReader_initFile(FILE *file, GTTlvReader **reader);

/*
 * Create a new reader for reading TLVs from a memory block.
 */
int GTTlvTReader_initMem(const void *data, const size_t data_len, GTTlvReader **reader);

/*
 * Read next TLV object from reader.
 */
int GTTlvReader_readTlv(GTTlvReader *rdr, GTTlv **outTlv);

/*
 * Frees the TLV object, but *not* the object referenced by the next pointer
 */
void GTTlv_free(GTTlv *tlv);

/*
 * Frees the reader object, but *does not* close the file and *does not* free the data pointer.
 */
void GTTlvReader_free(GTTlvReader *container);

/*
 * Parses an int value from the TLV payload.
 */
int GTTlv_getInt(const GTTlv *tlv, int *val);

/*
 * Reads TLVs until a LOGREC signature is read. All the intermediate TLVs and signature
 * TLV are linked with each other. The first and the last TLV of the linked list are
 * respectively \p blockFirst and \p blockLast.
 */
int GTTlv_readNextBlock (GTTlvReader *reader, GTTlv **blockFirst, GTTlv **blockLast);

/*
 * Appends raw data with TLV type and flags to buffer. Checks for overflow. Returns LOGSIG_OK on success.
 */
int bufAppendTlv(void *out_buf, size_t *out_buf_len, const size_t out_buf_size, const uint16_t type, uint8_t *in_buf, const size_t in_buf_len);

/*
 * Append unsigned int to the buffer in big-endian and removes all leading zero bytes but not the last one.
 */
int bufAppendTlvUint(void *out_buf, size_t *out_buf_len, size_t out_buf_size, uint16_t type, uint32_t value);

#ifdef __cplusplus
}
#endif


#endif
