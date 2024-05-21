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

#ifndef HMAC_H_
#define HMAC_H_

#include "hash.h"

void GT_Hmac_Setup(void);
void GT_Hmac_Cleanup(void);
int GT_Hmac_Calculate(GT_Hash_AlgorithmId alg, const void *key, size_t key_len, const void *data, size_t data_len, unsigned char *hsh, unsigned int *sz);
int GT_Hmac_IsAlgorithmsSupported(GT_Hash_AlgorithmId id);
const char *GT_Hmac_GetCryptoProvider();

#endif /* HMAC_H_ */
