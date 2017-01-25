/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2016] Guardtime, Inc
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

#ifndef GREP_TLV_H_
#define GREP_TLV_H_

#include "common.h"
#include "fast_tlv.h"

	typedef struct pattern_st GT_GrepPattern;

	#define IDX_MAP_LEN 0x1ffff

	typedef struct {
		size_t count;
		size_t element_count[IDX_MAP_LEN];
	} GT_ElementCounter;

	typedef struct {
		const char *file_name;
		GT_GrepPattern *pattern;
		int magic_len;
		bool print_tlv_hdr;
		bool print_tlv_hdr_only;
		bool print_raw;
		bool print_path;
		bool print_path_index;
		unsigned trunc_tlv_tag;
		size_t trunc_len;
	} GT_GrepTlvConf;

	void GT_GrepTlv_initConf(GT_GrepTlvConf *conf);

	int GT_grepTlv(GT_GrepTlvConf *conf, GT_GrepPattern *pattern, char *prefix, GT_ElementCounter *map, unsigned char *buf, GT_FTLV *t, unsigned char *raw, size_t *rlen);
	int GT_GrepPattern_parse(const char *in, GT_GrepPattern **out);
	void GT_GrepPattern_free(GT_GrepPattern *p);

#endif /* GREP_TLV_H_ */
