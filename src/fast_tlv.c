/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#include <stdlib.h>
#include <stdio.h>

#include "fast_tlv.h"
#include "tlvdump.h"

typedef int (*reader_t)(void *, unsigned char *, size_t, size_t *);

static int parseHdr(const unsigned char *hdr, size_t hdrLen, struct fast_tlv_s *t) {
	int res = KSI_UNKNOWN_ERROR;

	if (hdr == NULL || t == NULL) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	t->tag = hdr[0] & KSI_TLV_MASK_TLV8_TYPE;

	if (hdr[0] & KSI_TLV_MASK_TLV16) {
		if (hdrLen != 4) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}
		t->tag = ((t->tag << 8) | hdr[1]);
		t->dat_len = ((hdr[2] << 8) | hdr[3]) & 0xffff;
	} else {
		if (hdrLen != 2) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}
		t->dat_len = hdr[1];
	}

	t->hdr_len = hdrLen;
	t->is_nc = (hdr[0] & KSI_TLV_MASK_LENIENT) != 0;
	t->is_fwd = (hdr[0] & KSI_TLV_MASK_FORWARD) != 0;

	res = KSI_OK;

cleanup:

	return res;
}


int KSI_FTLV_fileRead(FILE *fd, unsigned char *buf, size_t len, size_t *consumed, struct fast_tlv_s *t) {
	int res = KSI_UNKNOWN_ERROR;
	size_t rd;
	size_t count = 0;

	if (fd == NULL || buf == NULL || len < 2 || t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	rd = fread(buf, 1, 2, fd);
	count += rd;

	if (rd != 2) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	if (buf[0] & KSI_TLV_MASK_TLV16) {
		if (len < 4) {
			res = KSI_BUFFER_OVERFLOW;
			goto cleanup;
		}

		rd = fread(buf + 2, 1, 2, fd);
		count += rd;

		if (rd != 2) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}

		res = parseHdr(buf, 4, t);
		if (res != KSI_OK) goto cleanup;

	} else {
		res = parseHdr(buf, 2, t);
		if (res != KSI_OK) goto cleanup;
	}

	if (len < t->hdr_len + t->dat_len) {
		res = KSI_BUFFER_OVERFLOW;
		goto cleanup;
	}

	if (t->dat_len > 0) {
		unsigned char *datap = buf + t->hdr_len;
		rd = fread(datap, 1, t->dat_len, fd);
		count += rd;

		if (rd != t->dat_len) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}
	}

	res = KSI_OK;

cleanup:

	if (consumed != NULL) *consumed = count;

	return res;
}

int KSI_FTLV_memRead(const unsigned char *m, size_t l, KSI_FTLV *t) {
	int res = KSI_UNKNOWN_ERROR;

	if (m == NULL || l < 2 || t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Initialize offset. */
	t->off = 0;

	if (m[0] & KSI_TLV_MASK_TLV16) {
		if (l < 4) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}
		res = parseHdr(m, 4, t);
		if (res != KSI_OK) goto cleanup;
	} else {
		res = parseHdr(m, 2, t);
		if (res != KSI_OK) goto cleanup;
	}

	if (l < t->hdr_len + t->dat_len) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_FTLV_memReadN(const unsigned char *buf, size_t buf_len, KSI_FTLV *arr, size_t arr_len, size_t *rd) {
	int res = KSI_UNKNOWN_ERROR;
	const unsigned char *ptr = buf;
	size_t len = buf_len;
	size_t i = 0;
	/* Dummy buffer, used if arr == NULL. */
	KSI_FTLV dummy;
	size_t off = 0;

	if (buf == NULL || buf_len == 0 || (arr != NULL && arr_len == 0) || (arr == NULL && arr_len != 0)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Read up-to arr_len tlvs from the buffer. */
	while ((arr_len == 0 || i < arr_len) && len > 0) {
		size_t tlvLen;
		KSI_FTLV *target = (arr == NULL ? &dummy : &arr[i]);

		/* Read the next tlv. */
		res = KSI_FTLV_memRead(ptr, len, target);
		if (res != KSI_OK) goto cleanup;

		target->off = off;

		/* Calculate consumed bytes. */
		tlvLen = target->hdr_len + target->dat_len;

		ptr += tlvLen;
		len -= tlvLen;
		off += tlvLen;
		++i;
	}

	/* If the output variable is set, evaluate it. */
	if (rd != NULL) {
		*rd = i;
	}

	res = KSI_OK;

cleanup:

	return res;
}
