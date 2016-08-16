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

#ifndef FAST_TLV_H_
#define FAST_TLV_H_

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct fast_tlv_s GT_FTLV;

	struct fast_tlv_s {
		/** Offset. */
		size_t off;

		/** Header lenght. */
		size_t hdr_len;

		/** Payload lenght. */
		size_t dat_len;

		/** TLV tag */
		unsigned tag;

		/* Flag - is non critical. */
		int is_nc;

		/* Flag - is forward. */
		int is_fwd;

		/* Flag to force TLV16. */
		int force16;
	};

	/**
	 * Read the TLV from a file.
	 * \param[in]	f			File descriptor.
	 * \param[in]	buf			Pointer to memory buffer.
	 * \param[in]	len			Length of the buffer.
	 * \param[out]	consumed	Number of bytes read.
	 * \param[in]	t			Pointer to  the #GT_FTLV object.
	 * \return status code (\c GT_OK, when operation succeeded, otherwise an error code).
	 */
	int GT_FTLV_fileRead(FILE *f, unsigned char *buf, size_t len, size_t *consumed, GT_FTLV *t);

	/**
	 * Read the TLV from a memory buffer.
	 * \param[in]	m		Pointer to the memory buffer.
	 * \param[in]	l		Length of the buffer.
	 * \param[in]	t		Pointer to the #GT_FTLV object.
	 * \return status code (\c GT_OK, when operation succeeded, otherwise an error code).
	 */
	int GT_FTLV_memRead(const unsigned char *m, size_t l, GT_FTLV *t);

	/**
	 * Reads up to \c arr_len TLV's  from the buffer. The number of read elements is returned via \c rd
	 * output parameter. If the \c arr pointer is set to \c NULL and \c arr_len equals 0, the function
	 * calculates the required length for the buffer \c arr.
	 * \param[in]	buf		Pointer to the memory buffer.
	 * \param[in]	buf_len	Length of the buffer.
	 * \param[in]	arr		Pointer to the output buffer (can be \c NULL).
	 * \param[in]	arr_len	Length of the output buffer (must be equal to 0, if \c arr is \c NULL).
	 * \param[out]	rd		Output parameter for the number of TLV read (can be \c NULL).
	 * \return status code (\c GT_OK, when operation succeeded, otherwise an error code).
	 * \note This method is using optimized to do as little copy operations as possible. In case of an
	 * error during this process, the buffer will probably get corrupted. If this corruption of the
	 * buffer is an issue, you may call this function twice - the first time just leave \c arr as \c NULL
	 * and \c arr_len equal to 0.
	 */
	int GT_FTLV_memReadN(const unsigned char *buf, size_t buf_len, GT_FTLV *arr, size_t arr_len, size_t *rd);


#ifdef __cplusplus
}
#endif

#endif /* FAST_TLV_H_ */
