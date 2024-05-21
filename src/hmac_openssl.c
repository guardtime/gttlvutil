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

#if CRYPTO_IMPL == HASH_OPENSSL

#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#	include <openssl/provider.h>
#endif


#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	static OSSL_PROVIDER *_legacy = NULL;
	static OSSL_PROVIDER *_default = NULL;

	void GT_Hmac_Setup(void) {
		_default = OSSL_PROVIDER_load(NULL, "default"); // To support ripemd160.
		_legacy = OSSL_PROVIDER_load(NULL, "legacy"); // To support ripemd160.
	}

	void GT_Hmac_Cleanup(void) {
		OSSL_PROVIDER_unload(_legacy);
		OSSL_PROVIDER_unload(_default);
	}
#else
	void GT_Hmac_Setup(void) {return;}
	void GT_Hmac_Cleanup(void) {return;}
#endif


#if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define EVP_MD_CTX_create_() EVP_MD_CTX_create()
#  define EVP_MD_CTX_destroy_(md) EVP_MD_CTX_destroy((md))
#  define EVP_MD_CTX_cleanup_(md) EVP_MD_CTX_cleanup((md))
#else
#  define EVP_MD_CTX_create_() EVP_MD_CTX_new()
#  define EVP_MD_CTX_destroy_(md) EVP_MD_CTX_free((md))
#  define EVP_MD_CTX_cleanup_(md) EVP_MD_CTX_reset((md))
#endif

/**
 * Converts hash function ID to OpenSSL identifier
 */
static const EVP_MD *hashAlgorithmToEVP(GT_Hash_AlgorithmId id)
{
	switch (id) {
#ifndef OPENSSL_NO_SHA
		case GT_HASHALG_SHA1:
			return EVP_sha1();
#endif
#ifndef OPENSSL_NO_RIPEMD
		case GT_HASHALG_RIPEMD160:
			return EVP_ripemd160();
#endif
		case GT_HASHALG_SHA2_256:
			return EVP_sha256();
#ifndef OPENSSL_NO_SHA512
		case GT_HASHALG_SHA2_384:
			return EVP_sha384();
		case GT_HASHALG_SHA2_512:
			return EVP_sha512();
#endif
		default:
			return NULL;
	}
}

int GT_Hmac_IsAlgorithmsSupported(GT_Hash_AlgorithmId id) {
	switch (id) {
#ifndef OPENSSL_NO_SHA
		case GT_HASHALG_SHA1:
#endif
#ifndef OPENSSL_NO_RIPEMD
		case GT_HASHALG_RIPEMD160:
#endif
		case GT_HASHALG_SHA2_256:
#ifndef OPENSSL_NO_SHA512
		case GT_HASHALG_SHA2_384:
		case GT_HASHALG_SHA2_512:
#endif
			return 1;
		default:
			return 0;
	}
}

const char *GT_Hmac_GetCryptoProvider() {
	return "OpenSSL";
}

static int initEvpCtx(GT_Hash_AlgorithmId alg, EVP_MD_CTX **ctx) {
	int res = GT_UNKNOWN_ERROR;

	if (ctx == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	*ctx = EVP_MD_CTX_create_();
	if (*ctx == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	EVP_MD_CTX_init(*ctx);

	res = GT_OK;
cleanup:
	return res;
}

static int prepareKeyForHashing(EVP_MD_CTX *ctx, const void *key, size_t key_len, size_t blocksize, unsigned char *ipad, unsigned char *opad) {
	int res = GT_UNKNOWN_ERROR;
	unsigned char tmp[GT_HASH_MAX_BLOCK_SIZE] = {0};
	unsigned int len;
	size_t i;

	if (key_len > blocksize) {
		if (!EVP_DigestUpdate(ctx, key, key_len)) {
			res = GT_CRYPTO_FAILURE;
			goto cleanup;
		}
		if (!EVP_DigestFinal_ex(ctx, tmp, &len)) {
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
	return res;
}

int GT_Hmac_Calculate(GT_Hash_AlgorithmId alg, const void *key, size_t key_len, const void *data, size_t data_len, unsigned char *hsh, unsigned int *sz) {
	int res = GT_UNKNOWN_ERROR;
	const EVP_MD *evp_md = hashAlgorithmToEVP(alg);
	EVP_MD_CTX *ctx = NULL;
	unsigned char ipad[GT_HASH_MAX_BLOCK_SIZE];
	unsigned char opad[GT_HASH_MAX_BLOCK_SIZE];
	size_t blockSize;
	unsigned char idig[GT_HASH_MAX_LEN] = {0};
	unsigned int idig_len;

	if (data_len == 0) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = initEvpCtx(alg, &ctx);
	if (res != GT_OK) goto cleanup;

	blockSize = GT_Hash_getAlgorithmBlockSize(alg);

	if (!EVP_DigestInit_ex(ctx, evp_md, NULL)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	res = prepareKeyForHashing(ctx, key, key_len, blockSize, ipad, opad);
	if (res != GT_OK) goto cleanup;

	if (!EVP_DigestInit_ex(ctx, evp_md, NULL)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	/* Calculate inner digest */
	if (!EVP_DigestUpdate(ctx, ipad, blockSize)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	if (!EVP_DigestUpdate(ctx, data, data_len)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	if (!EVP_DigestFinal_ex(ctx, idig, &idig_len)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	/* Calculate outer digest */
	if (!EVP_DigestInit_ex(ctx, evp_md, NULL)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	if (!EVP_DigestUpdate(ctx, opad, blockSize)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	if (!EVP_DigestUpdate(ctx, idig, idig_len)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	if (!EVP_DigestFinal_ex(ctx, hsh, sz)) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	/* Make sure the hash length is the same. */
	if (GT_Hash_getAlgorithmLenght(alg) != *sz) {
		res = GT_UNKNOWN_ERROR;
		goto cleanup;
	}

	res = GT_OK;
cleanup:

	if (ctx != NULL) {
		EVP_MD_CTX_cleanup_(ctx);
		EVP_MD_CTX_destroy_(ctx);
	}

	return res;
}

#endif /*CRYPTO_IMPL*/
