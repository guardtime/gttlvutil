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

#include "hmac.h"
#include "common.h"

#if CRYPTO_IMPL == HASH_CRYPTOAPI

#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>

/**
 * Converts hash function ID from hash chain to crypto api identifier
 */
static const ALG_ID hashAlgorithmToALG_ID(GT_Hash_AlgorithmId id)
{
	switch (id) {
		case GT_HASHALG_SHA1:
			return CALG_SHA1;
		case GT_HASHALG_SHA2_256:
			return CALG_SHA_256;
		case GT_HASHALG_SHA2_384:
			return CALG_SHA_384;
		case GT_HASHALG_SHA2_512:
			return CALG_SHA_512;
		default:
			return 0;
	}
}

static int prepareKeyForHashing(HCRYPTPROV cryptCtx, ALG_ID alg_id, const void *key, size_t key_len, size_t blocksize, unsigned char *ipad, unsigned char *opad) {
	int res = GT_UNKNOWN_ERROR;
	HCRYPTHASH cryptHash = 0;
	unsigned char tmp[GT_HASH_MAX_BLOCK_SIZE] = {0};
	unsigned int len;
	size_t i;

	if (key_len > blocksize) {
		if (!CryptCreateHash(cryptCtx, alg_id, 0, 0, &cryptHash))
		{
			res = GT_CRYPTO_FAILURE;
			goto cleanup;
		}

		if (!CryptHashData(cryptHash, key, (DWORD)key_len, 0))
		{
			res = GT_CRYPTO_FAILURE;
			goto cleanup;
		}

		if (!CryptGetHashParam(cryptHash, HP_HASHVAL, tmp, &len, 0))
		{
			res = GT_CRYPTO_FAILURE;
			goto cleanup;
		}
	} else {
		memcpy(tmp, key, key_len);
		len = (unsigned int)key_len;
	}

	if (len > blocksize) {
		res = GT_BUFFER_OVERFLOW;
		goto cleanup;
	}

	for (i = 0; i < blocksize; i++) {
		opad[i] = 0x5c ^ tmp[i];
		ipad[i] = 0x36 ^ tmp[i];
	}

	res = GT_OK;
cleanup:
	if (cryptHash) CryptDestroyHash(cryptHash);

	return res;
}

int GT_Hmac_Calculate(GT_Hash_AlgorithmId alg, const void *key, size_t key_len, const void *data, size_t data_len, unsigned char *hsh, unsigned int *sz) {
	int res = GT_UNKNOWN_ERROR;
	HCRYPTPROV cryptProv = 0;
	HCRYPTHASH cryptHash = 0;
	const ALG_ID alg_id = hashAlgorithmToALG_ID(alg);
	const DWORD blockSize = (DWORD)GT_Hash_getAlgorithmBlockSize(alg);
	unsigned char ipad[GT_HASH_MAX_BLOCK_SIZE];
	unsigned char opad[GT_HASH_MAX_BLOCK_SIZE];
	unsigned char idig[GT_HASH_MAX_LEN] = {0};
	DWORD idig_len;

	if (data_len == 0) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Create new crypto service provider (CSP). */
	if (!CryptAcquireContext(&cryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	res = prepareKeyForHashing(cryptProv, alg_id, key, key_len, blockSize, ipad, opad);
	if (res != GT_OK) goto cleanup;

	/* Calculate inner digest */
	if (!CryptCreateHash(cryptProv, alg_id, 0, 0, &cryptHash))
	{
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	if (!CryptHashData(cryptHash, ipad, blockSize, 0))
	{
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	if (!CryptHashData(cryptHash, data, (DWORD)data_len, 0))
	{
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	if (!CryptGetHashParam(cryptHash, HP_HASHVAL, idig, &idig_len, 0))
	{
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	/* Calculate outer digest */
	CryptDestroyHash(cryptHash);
	cryptHash = 0;
	if (!CryptCreateHash(cryptProv, alg_id, 0, 0, &cryptHash))
	{
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	if (!CryptHashData(cryptHash, opad, blockSize, 0))
	{
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	if (!CryptHashData(cryptHash, idig, idig_len, 0))
	{
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	if (!CryptGetHashParam(cryptHash, HP_HASHVAL, hsh, sz, 0))
	{
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	/* Make sure the hash length is the same. */
	if (GT_Hash_getAlgorithmLenght(alg) != *sz) {
		res = GT_BUFFER_OVERFLOW;
		goto cleanup;
	}

	res = GT_OK;
cleanup:
	if (cryptProv) CryptReleaseContext(cryptProv, 0);
	if (cryptHash) CryptDestroyHash(cryptHash);

	return res;
}

#endif /*CRYPTO_IMPL*/
