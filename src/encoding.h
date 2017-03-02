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

#ifndef GT_ENCODING_H
#define GT_ENCODING_H

#include "common.h"

typedef enum encoding_en {
	GT_BASE_2 = 0,
	GT_BASE_16,
	GT_BASE_64,
	GT_BASE_NA
} GT_Encoding;

/**
 * Decode Base-64 #GT_BASE_64 ASCII string into binary representation #GT_BASE_2.
 * \param encoded	Base64 encoded null terminated c string.
 * \param raw		Decoded binary data.
 * \param raw_len	Decoded data size.
 * \return	Status code (#GT_OK, when operation succeeded, otherwise an error code).
 * \note In case \c raw is NULL, then only decoded data length is calculated.
 */
int GT_Base64_decode(const char *encoded, unsigned char *raw, size_t *raw_len);

/**
 * Decode hexadecimal #GT_BASE_16 ASCII string into binary representation #GT_BASE_2.
 * \param encoded	Hexadecimal encoded null terminated c string.
 * \param raw		Decoded binary data.
 * \param raw_len	Decoded data size.
 * \return	Status code (#GT_OK, when operation succeeded, otherwise an error code).
 * \note In case \c raw is NULL, then only decoded data length is calculated.
 */
int GT_Base16_decode(const char *encoded, unsigned char *raw, size_t *raw_len);

/**
 * Calculate decoded data length based on the input data \c encoded.
 * \param enc		Encryption #GT_Encoding.
 * \param encoded	Encoded null terminated c string.
 * \return Decoded data length, or 0 in case of an error.
 */
size_t GT_GetDecodedSize(GT_Encoding enc, const char *encoded);

/**
 * Parse encoding parameter from cmd line.
 * \param enc	Encoding as c string.
 * \return A representation of the encoding from #GT_Encoding. In case of an error #GT_BASE_NA is returned.
 */
GT_Encoding GT_ParseEncoding(const char *enc);

#endif /* GT_ENCODING_H */
