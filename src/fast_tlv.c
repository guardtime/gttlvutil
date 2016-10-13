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
#include "common.h"

typedef int (*reader_t)(void *, unsigned char *, size_t, size_t *);

static int parseHdr(const unsigned char *hdr, size_t hdrLen, struct fast_tlv_s *t) {
	int res = GT_UNKNOWN_ERROR;

	if (hdr == NULL || t == NULL) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	t->tag = hdr[0] & GT_TLV_MASK_TLV8_TYPE;

	if (hdr[0] & GT_TLV_MASK_TLV16) {
		if (hdrLen != 4) {
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}
		t->tag = ((t->tag << 8) | hdr[1]);
		t->dat_len = ((hdr[2] << 8) | hdr[3]) & 0xffff;
	} else {
		if (hdrLen != 2) {
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}
		t->dat_len = hdr[1];
	}

	/* Eliminate false positives. */
	if (t->tag == 0 && t->dat_len == 0) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	t->hdr_len = hdrLen;
	t->is_nc = (hdr[0] & GT_TLV_MASK_NON_CRITICAL) != 0;
	t->is_fwd = (hdr[0] & GT_TLV_MASK_FORWARD) != 0;

	/* Set the force flag to indicate TLV that could be TLV8,
	 * but for some reason are encoded as TLV16. */
	if (t->tag <= 0x1f && t->hdr_len <= 0xff) {
		t->force16 = (hdr[0] & GT_TLV_MASK_TLV16) != 0;
	}

	res = GT_OK;

cleanup:

	return res;
}


int GT_FTLV_fileRead(FILE *fd, unsigned char *buf, size_t len, size_t *consumed, GT_FTLV *t) {
	int res = GT_UNKNOWN_ERROR;
	size_t rd;
	size_t count = 0;

	if (fd == NULL || buf == NULL || len < 2 || t == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	rd = fread(buf, 1, 2, fd);
	count += rd;

	if (rd != 2) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	if (buf[0] & GT_TLV_MASK_TLV16) {
		if (len < 4) {
			res = GT_BUFFER_OVERFLOW;
			goto cleanup;
		}

		rd = fread(buf + 2, 1, 2, fd);
		count += rd;

		if (rd != 2) {
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}

		res = parseHdr(buf, 4, t);
		if (res != GT_OK) goto cleanup;

	} else {
		res = parseHdr(buf, 2, t);
		if (res != GT_OK) goto cleanup;
	}

	/* Make sure the TLV fits into the original buffer. */
	if (len < t->hdr_len + t->dat_len) {
		res = GT_BUFFER_OVERFLOW;
		goto cleanup;
	}

	if (t->dat_len > 0) {
		unsigned char *datap = buf + t->hdr_len;
		rd = fread(datap, 1, t->dat_len, fd);
		count += rd;

		if (rd != t->dat_len) {
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}
	}

	res = GT_OK;

cleanup:

	if (consumed != NULL) *consumed = count;

	return res;
}

int GT_FTLV_memRead(const unsigned char *m, size_t l, GT_FTLV *t) {
	int res = GT_UNKNOWN_ERROR;

	if (m == NULL || l < 2 || t == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Initialize offset. */
	t->off = 0;

	if (m[0] & GT_TLV_MASK_TLV16) {
		if (l < 4) {
			res = GT_INVALID_FORMAT;
			goto cleanup;
		}
		res = parseHdr(m, 4, t);
		if (res != GT_OK) goto cleanup;
	} else {
		res = parseHdr(m, 2, t);
		if (res != GT_OK) goto cleanup;
	}

	if (l < t->hdr_len + t->dat_len) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	res = GT_OK;

cleanup:

	return res;
}

int GT_FTLV_memReadN(const unsigned char *buf, size_t buf_len, GT_FTLV *arr, size_t arr_len, size_t *rd) {
	int res = GT_UNKNOWN_ERROR;
	const unsigned char *ptr = buf;
	size_t len = buf_len;
	size_t i = 0;
	/* Dummy buffer, used if arr == NULL. */
	GT_FTLV dummy;
	size_t off = 0;

	if (buf == NULL || buf_len == 0 || (arr != NULL && arr_len == 0) || (arr == NULL && arr_len != 0)) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Read up-to arr_len tlvs from the buffer. */
	while ((arr_len == 0 || i < arr_len) && len > 0) {
		size_t tlvLen;
		GT_FTLV *target = (arr == NULL ? &dummy : &arr[i]);

		/* Read the next tlv. */
		res = GT_FTLV_memRead(ptr, len, target);
		if (res != GT_OK) goto cleanup;

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

	res = GT_OK;

cleanup:

	return res;
}
