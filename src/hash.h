/*
 * Copyright 2013-2016 Guardtime, Inc.
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

#ifndef HASH_H_
#define HASH_H_

#include "common.h"

#define GT_HASH_MAX_LEN 64 /* Longest digest */

#define GT_HASH_MAX_BLOCK_SIZE (1024/8)

/**
 * Guardtime representation of hash algorithms
 */
typedef enum {
	/** The SHA-1 algorithm. */
	GT_HASHALG_SHA1 = 0x00,
	/** The SHA-256 algorithm. */
	GT_HASHALG_SHA2_256 = 0x01,
	/** The RIPEMD-160 algorithm. */
	GT_HASHALG_RIPEMD160 = 0x02,
	/** Unsupported algorithm. */
	GT_HASHALG_UNKNOWN_03 = 0x03,
	/** The SHA-384 algorithm. */
	GT_HASHALG_SHA2_384 = 0x04,
	/** The SHA-512 algorithm. */
	GT_HASHALG_SHA2_512 = 0x05,

	GT_NOF_HASHALGS
} GT_Hash_AlgorithmId;

int GT_Hash_getAlgorithmId(char *arg, GT_Hash_AlgorithmId *id);
size_t GT_Hash_getAlgorithmLenght(GT_Hash_AlgorithmId id);
size_t GT_Hash_getAlgorithmBlockSize(GT_Hash_AlgorithmId id);
char* GT_Hash_getAlgorithmName(GT_Hash_AlgorithmId id);

#endif /* HASH_H_ */
