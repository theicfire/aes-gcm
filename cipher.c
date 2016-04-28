/**
 * \file cipher.c
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

#include <stdio.h>
#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CIPHER_C)

#include "cipher.h"
#include "cipher_internal.h"

#include "utils.h"

#if defined(MBEDTLS_GCM_C)
#include "gcm.h"
#endif

#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_NULL_CIPHER)
#define MBEDTLS_CIPHER_MODE_STREAM
#endif

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

static int supported_init = 0;


const mbedtls_cipher_info_t *mbedtls_cipher_info_from_values( const mbedtls_cipher_id_t cipher_id,
                                              int key_bitlen,
                                              const mbedtls_cipher_mode_t mode )
{
    const mbedtls_cipher_definition_t *def;

    for( def = mbedtls_cipher_definitions; def->info != NULL; def++ ) {
        if( def->info->base->cipher == cipher_id &&
            def->info->key_bitlen == (unsigned) key_bitlen &&
            def->info->mode == mode )
            return( def->info );
    }

    return( NULL );
}

void mbedtls_cipher_init( mbedtls_cipher_context_t *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_cipher_context_t ) );
}

void mbedtls_cipher_free( mbedtls_cipher_context_t *ctx )
{
    if( ctx == NULL )
        return;

    if( ctx->cipher_ctx )
        ctx->cipher_info->base->ctx_free_func( ctx->cipher_ctx );

    mbedtls_zeroize( ctx, sizeof(mbedtls_cipher_context_t) );
}

int mbedtls_cipher_setup( mbedtls_cipher_context_t *ctx, const mbedtls_cipher_info_t *cipher_info )
{
    if( NULL == cipher_info || NULL == ctx )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    memset( ctx, 0, sizeof( mbedtls_cipher_context_t ) );

    if( NULL == ( ctx->cipher_ctx = cipher_info->base->ctx_alloc_func() ) )
        return( MBEDTLS_ERR_CIPHER_ALLOC_FAILED );

    ctx->cipher_info = cipher_info;

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    /*
     * Ignore possible errors caused by a cipher mode that doesn't use padding
     */
#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)
    (void) mbedtls_cipher_set_padding_mode( ctx, MBEDTLS_PADDING_PKCS7 );
#else
    (void) mbedtls_cipher_set_padding_mode( ctx, MBEDTLS_PADDING_NONE );
#endif
#endif /* MBEDTLS_CIPHER_MODE_WITH_PADDING */

    return( 0 );
}

int mbedtls_cipher_setkey( mbedtls_cipher_context_t *ctx, const unsigned char *key,
        int key_bitlen, const mbedtls_operation_t operation )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( ( ctx->cipher_info->flags & MBEDTLS_CIPHER_VARIABLE_KEY_LEN ) == 0 &&
        (int) ctx->cipher_info->key_bitlen != key_bitlen )
    {
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    ctx->key_bitlen = key_bitlen;
    ctx->operation = operation;

    /*
     * For CFB and CTR mode always use the encryption key schedule
     */
    if( MBEDTLS_ENCRYPT == operation ||
        MBEDTLS_MODE_CFB == ctx->cipher_info->mode ||
        MBEDTLS_MODE_CTR == ctx->cipher_info->mode )
    {
        return ctx->cipher_info->base->setkey_enc_func( ctx->cipher_ctx, key,
                ctx->key_bitlen );
    }

    if( MBEDTLS_DECRYPT == operation )
        return ctx->cipher_info->base->setkey_dec_func( ctx->cipher_ctx, key,
                ctx->key_bitlen );

    return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
}

int mbedtls_cipher_set_iv( mbedtls_cipher_context_t *ctx,
                   const unsigned char *iv, size_t iv_len )
{
    size_t actual_iv_size;

    if( NULL == ctx || NULL == ctx->cipher_info || NULL == iv )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    /* avoid buffer overflow in ctx->iv */
    if( iv_len > MBEDTLS_MAX_IV_LENGTH )
        return( MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );

    if( ( ctx->cipher_info->flags & MBEDTLS_CIPHER_VARIABLE_IV_LEN ) != 0 )
        actual_iv_size = iv_len;
    else
    {
        actual_iv_size = ctx->cipher_info->iv_size;

        /* avoid reading past the end of input buffer */
        if( actual_iv_size > iv_len )
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    memcpy( ctx->iv, iv, actual_iv_size );
    ctx->iv_size = actual_iv_size;

    return( 0 );
}

int mbedtls_cipher_reset( mbedtls_cipher_context_t *ctx )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    ctx->unprocessed_len = 0;

    return( 0 );
}

#if defined(MBEDTLS_GCM_C)
int mbedtls_cipher_update_ad( mbedtls_cipher_context_t *ctx,
                      const unsigned char *ad, size_t ad_len )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( MBEDTLS_MODE_GCM == ctx->cipher_info->mode )
    {
        return mbedtls_gcm_starts( (mbedtls_gcm_context *) ctx->cipher_ctx, ctx->operation,
                           ctx->iv, ctx->iv_size, ad, ad_len );
    }

    return( 0 );
}
#endif /* MBEDTLS_GCM_C */

int mbedtls_cipher_update( mbedtls_cipher_context_t *ctx, const unsigned char *input,
                   size_t ilen, unsigned char *output, size_t *olen )
{
    int ret;

    if( NULL == ctx || NULL == ctx->cipher_info || NULL == olen )
    {
        printf("bad cipher_info!!");
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    *olen = 0;

    if( ctx->cipher_info->mode == MBEDTLS_MODE_ECB )
    {
        if( ilen != mbedtls_cipher_get_block_size( ctx ) ) {
            printf("bb\n");
            return( MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED );
        }

        *olen = ilen;

        if( 0 != ( ret = ctx->cipher_info->base->ecb_func( ctx->cipher_ctx,
                    ctx->operation, input, output ) ) )
        {
            printf("cc\n");
            return( ret );
        }

        return( 0 );
    }

#if defined(MBEDTLS_GCM_C)
    if( ctx->cipher_info->mode == MBEDTLS_MODE_GCM )
    {
        *olen = ilen;
        return mbedtls_gcm_update( (mbedtls_gcm_context *) ctx->cipher_ctx, ilen, input,
                           output );
    }
#endif

    if( input == output &&
       ( ctx->unprocessed_len != 0 || ilen % mbedtls_cipher_get_block_size( ctx ) ) )
    {
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }



    return( MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
}


int mbedtls_cipher_finish( mbedtls_cipher_context_t *ctx,
                   unsigned char *output, size_t *olen )
{
    if( NULL == ctx || NULL == ctx->cipher_info || NULL == olen )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    *olen = 0;

    if( MBEDTLS_MODE_CFB == ctx->cipher_info->mode ||
        MBEDTLS_MODE_CTR == ctx->cipher_info->mode ||
        MBEDTLS_MODE_GCM == ctx->cipher_info->mode ||
        MBEDTLS_MODE_STREAM == ctx->cipher_info->mode )
    {
        return( 0 );
    }

    if( MBEDTLS_MODE_ECB == ctx->cipher_info->mode )
    {
        if( ctx->unprocessed_len != 0 )
            return( MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED );

        return( 0 );
    }

    ((void) output);

    return( MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );
}


#if defined(MBEDTLS_GCM_C)
int mbedtls_cipher_write_tag( mbedtls_cipher_context_t *ctx,
                      unsigned char *tag, size_t tag_len )
{
    if( NULL == ctx || NULL == ctx->cipher_info || NULL == tag )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( MBEDTLS_ENCRYPT != ctx->operation )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( MBEDTLS_MODE_GCM == ctx->cipher_info->mode )
        return mbedtls_gcm_finish( (mbedtls_gcm_context *) ctx->cipher_ctx, tag, tag_len );

    return( 0 );
}

int mbedtls_cipher_check_tag( mbedtls_cipher_context_t *ctx,
                      const unsigned char *tag, size_t tag_len )
{
    int ret;

    if( NULL == ctx || NULL == ctx->cipher_info ||
        MBEDTLS_DECRYPT != ctx->operation )
    {
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    if( MBEDTLS_MODE_GCM == ctx->cipher_info->mode )
    {
        unsigned char check_tag[16];
        size_t i;
        int diff;

        if( tag_len > sizeof( check_tag ) )
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

        if( 0 != ( ret = mbedtls_gcm_finish( (mbedtls_gcm_context *) ctx->cipher_ctx,
                                     check_tag, tag_len ) ) )
        {
            return( ret );
        }

        /* Check the tag in "constant-time" */
        for( diff = 0, i = 0; i < tag_len; i++ )
            diff |= tag[i] ^ check_tag[i];

        if( diff != 0 )
            return( MBEDTLS_ERR_CIPHER_AUTH_FAILED );

        return( 0 );
    }

    return( 0 );
}
#endif /* MBEDTLS_GCM_C */

#endif /* MBEDTLS_CIPHER_C */
