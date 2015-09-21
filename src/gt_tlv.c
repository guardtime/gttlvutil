#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "gt_tlv.h"
#include "common.h"

#define gt_new(typeVar) (typeVar *) calloc(sizeof(typeVar), 1)

static int GTTlvReader_ended(GTTlvReader *reader) {
	if (reader->file != NULL) {
		return feof(reader->file);
	} else {
		return reader->relativeOffset == reader->data_len;
	}
}

static int readData(uint8_t *ptr, size_t len, GTTlvReader *reader) {
	int res = 0;
	if (reader->file != NULL) {
		res = fread(ptr, 1, len, reader->file);
	} else {
		const uint8_t *src = reader->data + reader->relativeOffset;
		while ((reader->relativeOffset + res) < reader->data_len && res < len) {
			*(ptr + res) = *(src++);
			res++;
		}
	}
	reader->relativeOffset += res;
	return res;
}

/**
 * Writes value to buffer by trimming leading zeors. On success returns LOGSIG_OK.
 */
static int bufAppendUint(uint8_t *buf, size_t *buf_len, size_t buf_size, uint32_t val) {
	int res = GT_UNKNOWN_ERROR;
	int len = 0;
	int i;
	for (i = sizeof(val) - 1; i >= 0; i--) {
		uint8_t bVal = (val >> (8*i)) & 0xff;
		if (i == 0 || len > 0 || bVal != 0x00) {
			if (*buf_len + len >= buf_size) {
				res = GT_FORMAT_ERROR;
				goto cleanup;
			}
			*(buf + *buf_len + len) = bVal;
			++len;
		}
	}
	*buf_len += len;

	res = GT_OK;
cleanup:
	return res;
}

/**
 * Append raw data to buffer. Checks for overflow. Returns GT_OK on success.
 */
static int bufAppendRaw(void *out_buf, size_t *out_buf_len, const size_t out_buf_size, const void *in_buf, const size_t in_buf_len) {
	int res = GT_UNKNOWN_ERROR;
	if (*out_buf_len + in_buf_len >= out_buf_size) {
		res = GT_FORMAT_ERROR;
		goto cleanup;
	}

	memcpy((unsigned char *)out_buf + *out_buf_len, in_buf, in_buf_len);
	*out_buf_len += in_buf_len;

	res = GT_OK;
cleanup:
	return res;
}

int GTTlvReader_readTlv(GTTlvReader *rdr, GTTlv **outTlv) {
	int res = GT_UNKNOWN_ERROR;
	uint8_t *raw_data;
	
	GTTlv *tlv = NULL;
	int read;

	tlv = gt_new(GTTlv);

	if (tlv == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tlv->relativeOffset = rdr->relativeOffset;
	tlv->next = NULL;
	tlv->payload = NULL;

	if ((read = readData(tlv->header, 2, rdr)) != 2) {
		if (read != 0 || !GTTlvReader_ended(rdr)) { // not end of file
			res = GT_FORMAT_ERROR;
		} else {
			res = GT_OK;
			*outTlv = NULL;
		}
		goto cleanup;
	}

	if (GT_is_tlv_flag_tlv16(tlv)) { // long format
		tlv->type = ((tlv->header[0] & 0x1f) << 8 ) | tlv->header[1];

		tlv->header_len = 4;

		if (readData(tlv->header + 2, 2, rdr) != 2) {
			res = GT_FORMAT_ERROR;
			goto cleanup;
		}
		tlv->payload_length = ((size_t) tlv->header[2] << 8) | (size_t)tlv->header[3];
	} else { // short format
		tlv->header_len = 2;
		tlv->type = (size_t) tlv->header[0] & 0x1f;
		tlv->payload_length = (size_t) tlv->header[1];
	}

	raw_data = calloc(tlv->payload_length, sizeof(char));
	if (raw_data == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if ((read = readData(raw_data, tlv->payload_length, rdr)) != tlv->payload_length) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tlv->payload = raw_data;

    *outTlv = tlv;
    tlv = NULL;

    res = GT_OK;
cleanup:
	GTTlv_free(tlv);
	return res;
}

/*
 * Does not close the stream nor does free the memory of data.
 */
void GTTlvReader_free(GTTlvReader *reader) {
	free(reader);
}

int GTTlvTReader_initFile(FILE *file, GTTlvReader **reader){
	int res = GT_UNKNOWN_ERROR;

	GTTlvReader *rdr = gt_new(GTTlvReader);
	if (rdr == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	rdr->data = NULL;
	rdr->data_len = 0;
	rdr->relativeOffset = 0;
	rdr->file = file;

	*reader = rdr;
	rdr = NULL;

	res = GT_OK;
cleanup:
	GTTlvReader_free(rdr);
	return res;
}

int GTTlvTReader_initMem(const void *data, const size_t data_len, GTTlvReader **reader){
	int res = GT_UNKNOWN_ERROR;

	GTTlvReader *rdr = gt_new(GTTlvReader);
	if (rdr == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	rdr->data = data;
	rdr->data_len = data_len;
	rdr->relativeOffset = 0;
	rdr->file = NULL;

	*reader = rdr;
	rdr = NULL;

	res = GT_OK;
cleanup:
	GTTlvReader_free(rdr);
	return res;
}

int GTTlv_getInt(const GTTlv *tlv, int *val) {
	int res = GT_UNKNOWN_ERROR;
	int tmp = 0;
	int i;

	if (tlv->payload_length > sizeof(int)) {
		res = GT_FORMAT_ERROR;
		goto cleanup;
	}

	for (i = 0; i < tlv->payload_length; i++) {
		tmp = (tmp << 8) | *(tlv->payload + i);
	}
	*val = tmp;

	res = GT_OK;
cleanup:
	return res;
}

int GTTlv_readNextBlock (GTTlvReader *reader, GTTlv **blockFirst, GTTlv **blockLast) {
	int res = GT_UNKNOWN_ERROR;
	GTTlv *first = NULL;
	GTTlv *last = NULL;
	GTTlv *tmp = NULL;

	while (1) {
		res = GTTlvReader_readTlv(reader, &tmp);

		if (res != GT_OK) {
			goto cleanup;
		}

		/* End of input */
		if (tmp == NULL) {
			res = GT_OK;
			goto cleanup;
		}

		if (first == NULL) {
			first = tmp;
		} else {
			last->next = tmp;
		}

		last = tmp;

		if (tmp->type == 0x0902) {
			break;
		}
	}

	if (last == NULL || last->type != 0x0902) {
		res = GT_FORMAT_ERROR;
		goto cleanup;
	}

	*blockFirst = first;
	*blockLast = last;

	res = GT_OK;

cleanup:
	/* Cleanup when error occured or end of input */
	if (res != GT_OK || first == NULL) {
		GTTlv_free(tmp);
		GTTlv_free(first);
	}


	return res;
}

void GTTlv_free(GTTlv *tlv) {
	if (tlv != NULL) {
		GTTlv_free(tlv->next);
		free(tlv->payload);
		free(tlv);
	}
}

int GTTlv_updateValue(GTTlv *tlv, const uint8_t *data, const size_t data_length) {
	int res = GT_UNKNOWN_ERROR;
	uint8_t *raw_data = NULL;

	/* Validate data length */
	if ((tlv->header_len < 4 && data_length >= 0xff) || data_length >= 0xffff ) {
		res = GT_FORMAT_ERROR;
		goto cleanup;
	}

	raw_data = malloc(data_length);

	if (raw_data == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}


	/* Update TLV length */
	switch(tlv->header_len) {
		case 4:
			tlv->header[3] = data_length & 0xff;
			tlv->header[2] = (data_length >> 8) & 0xff;
			break;
		case 2:
			tlv->header[1] = data_length & 0xff;
			break;
		default:
			res = GT_INVALID_ARGUMENT;
			goto cleanup;
	}

	memcpy(raw_data, data, data_length);

	free(tlv->payload);
	tlv->payload = raw_data;
	tlv->payload_length = data_length;

	res = GT_OK;
cleanup:
	if (res != GT_OK) {
		free(raw_data);
	}
	return res;
}

/*
 * Append GTTlv object to the buffer.
 */
int bufAppendGTTlv(void *out_buf, size_t *out_buf_len, const size_t out_buf_size, const GTTlv *tlv) {
	int res = GT_UNKNOWN_ERROR;
	size_t len = *out_buf_len;

	res = bufAppendRaw(out_buf, &len, out_buf_size, tlv->header, tlv->header_len);
	if (res != GT_OK) {
		goto cleanup;
	}

	res = bufAppendRaw(out_buf, &len, out_buf_size, tlv->payload, tlv->payload_length);

	*out_buf_len = len;
	res = GT_OK;
cleanup:
	return res;
}

/**
 * Appends raw data with TLV type and flags to buffer. Checks for overflow. Returns GT_OK on success.
 */
int bufAppendTlv(void *out_buf, size_t *out_buf_len, const size_t out_buf_size, const uint16_t type, uint8_t *in_buf, const size_t in_buf_len) {
	int res = GT_UNKNOWN_ERROR;
	uint8_t header[4];
	size_t header_len;
	size_t len;
	
	if (type & 0xe000) {
		res = GT_FORMAT_ERROR;
		goto cleanup;
	}
	if (type & 0x1fe0) {
		/* TLV16 */
		header_len = 4;
		header[0] = 0x80 | ((0x1f00 & type) >> 8);
		header[1] = 0x00ff & type;
		header[2] = (0xff00 & in_buf_len) >> 8;
		header[3] = 0x00ff & in_buf_len;

	} else {
		/* TLV8 */
		header_len = 2;
		/* Flags are 000 */
		header[0] = 0x001f & type;
		header[1] = 0x00ff & in_buf_len;
	}
	len = *out_buf_len;

	res = bufAppendRaw(out_buf, &len, out_buf_size, header, header_len);


	if (res != GT_OK) {
		goto cleanup;
	}

	res = bufAppendRaw(out_buf, &len, out_buf_size, in_buf, in_buf_len);

	if (res != GT_OK) {
		goto cleanup;
	}

	*out_buf_len = len;

	res = GT_OK;

cleanup:
	return res;
}

int bufAppendTlvUint(void *out_buf, size_t *out_buf_len, size_t out_buf_size, uint16_t type, uint32_t value) {
	int res = GT_UNKNOWN_ERROR;
	uint8_t buf[sizeof(value)];
	size_t buf_len = 0;
	size_t len = *out_buf_len;
	res = bufAppendUint(buf, &buf_len, sizeof(buf), value);
	if (res != GT_OK) {
		goto cleanup;
	}

	res = bufAppendTlv(out_buf, &len, out_buf_size, type, buf, buf_len);

	if (res != GT_OK) {
		goto cleanup;
	}

	*out_buf_len = len;

	res = GT_OK;
cleanup:
	return res;
}
