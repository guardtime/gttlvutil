/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

#ifndef _GT_ENCODING_H_
#define _GT_ENCODING_H_

#include "common.h"

typedef enum encoding_en {
	GT_BASE_2,
	GT_BASE_16,
	GT_BASE_32,
	GT_BASE_64,
	GT_BASE_NA
} GT_Encoding;

int GT_Base64_decode(const char *encoded, unsigned char **data, size_t *data_len);
int GT_Base64_encode(const unsigned char *data, const size_t data_len, char **encoded);

int GT_Base16_decode(const char *encoded, unsigned char **data, size_t *data_len);
int GT_Base16_encode(const unsigned char *data, const size_t data_len, char **encoded);

GT_Encoding GT_ParseEncoding(const char *enc);

#endif /* _GT_ENCODING_H_ */
