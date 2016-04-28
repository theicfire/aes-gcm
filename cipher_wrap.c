/**
 * \file cipher_wrap.c
 *
 * \brief Generic cipher wrapper for mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include "config.h"

#if defined(MBEDTLS_CIPHER_C)

#include "cipher_internal.h"

#if defined(MBEDTLS_AES_C)
#include "aes.h"
#endif

#if defined(MBEDTLS_GCM_C)
#include "gcm.h"
#endif


static mbedtls_gcm_context gcm_ctx;
static mbedtls_aes_context aes_ctx;
#if defined(MBEDTLS_CCM_C)
static mbedtls_ccm_context ccm_ctx;
#endif

#if defined(MBEDTLS_GCM_C)
/* shared by all GCM ciphers */
static void *gcm_ctx_alloc( void )
{
    void *ctx = &gcm_ctx;

    if( ctx != NULL )
        mbedtls_gcm_init( (mbedtls_gcm_context *) ctx );

    return( ctx );
}

static void gcm_ctx_free( void *ctx )
{
    mbedtls_gcm_free( ctx );
    /*mbedtls_free( ctx );*/
}
#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_AES_C)

static int aes_crypt_ecb_wrap( void *ctx, mbedtls_operation_t operation,
        const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_ecb( (mbedtls_aes_context *) ctx, operation, input, output );
}

static int aes_setkey_dec_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return mbedtls_aes_setkey_dec( (mbedtls_aes_context *) ctx, key, key_bitlen );
}

static int aes_setkey_enc_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return mbedtls_aes_setkey_enc( (mbedtls_aes_context *) ctx, key, key_bitlen );
}

static void * aes_ctx_alloc( void )
{
    mbedtls_aes_context *aes = &aes_ctx;

    if( aes == NULL )
        return( NULL );

    mbedtls_aes_init( aes );

    return( aes );
}

static void aes_ctx_free( void *ctx )
{
    mbedtls_aes_free( (mbedtls_aes_context *) ctx );
    /*mbedtls_free( ctx );*/
}

static const mbedtls_cipher_base_t aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    aes_crypt_ecb_wrap,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    aes_crypt_cbc_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    aes_crypt_cfb128_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    aes_crypt_ctr_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    aes_setkey_enc_wrap,
    aes_setkey_dec_wrap,
    aes_ctx_alloc,
    aes_ctx_free
};

static const mbedtls_cipher_info_t aes_128_ecb_info = {
    MBEDTLS_CIPHER_AES_128_ECB,
    MBEDTLS_MODE_ECB,
    128,
    "AES-128-ECB",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_192_ecb_info = {
    MBEDTLS_CIPHER_AES_192_ECB,
    MBEDTLS_MODE_ECB,
    192,
    "AES-192-ECB",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_256_ecb_info = {
    MBEDTLS_CIPHER_AES_256_ECB,
    MBEDTLS_MODE_ECB,
    256,
    "AES-256-ECB",
    16,
    0,
    16,
    &aes_info
};

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static const mbedtls_cipher_info_t aes_128_cbc_info = {
    MBEDTLS_CIPHER_AES_128_CBC,
    MBEDTLS_MODE_CBC,
    128,
    "AES-128-CBC",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_192_cbc_info = {
    MBEDTLS_CIPHER_AES_192_CBC,
    MBEDTLS_MODE_CBC,
    192,
    "AES-192-CBC",
    16,
    0,
    16,
    &aes_info
};

static const mbedtls_cipher_info_t aes_256_cbc_info = {
    MBEDTLS_CIPHER_AES_256_CBC,
    MBEDTLS_MODE_CBC,
    256,
    "AES-256-CBC",
    16,
    0,
    16,
    &aes_info
};
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_GCM_C)
static int gcm_aes_setkey_wrap( void *ctx, const unsigned char *key,
                                unsigned int key_bitlen )
{
    return mbedtls_gcm_setkey( (mbedtls_gcm_context *) ctx, MBEDTLS_CIPHER_ID_AES,
                     key, key_bitlen );
}

static const mbedtls_cipher_base_t gcm_aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    gcm_aes_setkey_wrap,
    gcm_aes_setkey_wrap,
    gcm_ctx_alloc,
    gcm_ctx_free,
};

static const mbedtls_cipher_info_t aes_128_gcm_info = {
    MBEDTLS_CIPHER_AES_128_GCM,
    MBEDTLS_MODE_GCM,
    128,
    "AES-128-GCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};

static const mbedtls_cipher_info_t aes_192_gcm_info = {
    MBEDTLS_CIPHER_AES_192_GCM,
    MBEDTLS_MODE_GCM,
    192,
    "AES-192-GCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};

static const mbedtls_cipher_info_t aes_256_gcm_info = {
    MBEDTLS_CIPHER_AES_256_GCM,
    MBEDTLS_MODE_GCM,
    256,
    "AES-256-GCM",
    12,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    16,
    &gcm_aes_info
};
#endif /* MBEDTLS_GCM_C */

#endif /* MBEDTLS_AES_C */

const mbedtls_cipher_definition_t mbedtls_cipher_definitions[] =
{
#if defined(MBEDTLS_AES_C)
    { MBEDTLS_CIPHER_AES_128_ECB,          &aes_128_ecb_info },
    { MBEDTLS_CIPHER_AES_192_ECB,          &aes_192_ecb_info },
    { MBEDTLS_CIPHER_AES_256_ECB,          &aes_256_ecb_info },
#if defined(MBEDTLS_GCM_C)
    { MBEDTLS_CIPHER_AES_128_GCM,          &aes_128_gcm_info },
    { MBEDTLS_CIPHER_AES_192_GCM,          &aes_192_gcm_info },
    { MBEDTLS_CIPHER_AES_256_GCM,          &aes_256_gcm_info },
#endif
#if defined(MBEDTLS_CCM_C)
    { MBEDTLS_CIPHER_AES_128_CCM,          &aes_128_ccm_info },
    { MBEDTLS_CIPHER_AES_192_CCM,          &aes_192_ccm_info },
    { MBEDTLS_CIPHER_AES_256_CCM,          &aes_256_ccm_info },
#endif
#endif /* MBEDTLS_AES_C */

    { MBEDTLS_CIPHER_NONE, NULL }
};

#define NUM_CIPHERS sizeof mbedtls_cipher_definitions / sizeof mbedtls_cipher_definitions[0]
int mbedtls_cipher_supported[NUM_CIPHERS];

#endif /* MBEDTLS_CIPHER_C */
