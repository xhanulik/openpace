/*
 * Copyright (c) 2010-2012 Frank Morgner and Dominik Oepen
 *
 * This file is part of OpenPACE.
 *
 * OpenPACE is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * OpenPACE is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * OpenPACE.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with OpenSSL (or a modified version of that library), containing
 * parts covered by the terms of OpenSSL's license, the licensors of
 * this Program grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination shall include
 * the source code for the parts of OpenSSL used as well as that of the
 * covered work.
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with OpenSC (or a modified version of that library), containing
 * parts covered by the terms of OpenSC's license, the licensors of
 * this Program grant you additional permission to convey the resulting work. 
 * Corresponding Source for a non-source form of such a combination shall include
 * the source code for the parts of OpenSC used as well as that of the
 * covered work.
 */

/**
 * @file eac_ecdh.c
 * @brief Elliptic curve Diffie Hellman helper functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_ecdh.h"
#include "eac_err.h"
#include "misc.h"
#include <eac/pace.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#endif
#include <openssl/ec.h>
#include <openssl/objects.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
int
init_ecdh(EC_KEY ** ecdh, int standardizedDomainParameters)
{
    int r = 0;
    EC_KEY * tmp = NULL;

    if (!ecdh) {
        log_err("Invalid arguments");
        return 0;
    }

    switch(standardizedDomainParameters) {
        case 8:
            /* NOTE: prime192v1 is equivalent to secp192r1 */
            tmp = EC_KEY_new_by_curve_name(NID_X9_62_prime192v1);
            break;
        case 9:
            tmp = EC_KEY_new_by_curve_name(NID_brainpoolP192r1);
            break;
        case 10:
            tmp = EC_KEY_new_by_curve_name(NID_secp224r1);
            break;
        case 11:
            tmp = EC_KEY_new_by_curve_name(NID_brainpoolP224r1);
            break;
        case 12:
            /* NOTE: prime256v1 is equivalent to secp256r1 */
            tmp = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            break;
        case 13:
            tmp = EC_KEY_new_by_curve_name(NID_brainpoolP256r1);
            break;
        case 14:
            tmp = EC_KEY_new_by_curve_name(NID_brainpoolP320r1);
            break;
        case 15:
            tmp = EC_KEY_new_by_curve_name(NID_secp384r1);
            break;
        case 16:
            tmp = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
            break;
        case 17:
            tmp = EC_KEY_new_by_curve_name(NID_brainpoolP512r1);
            break;
        case 18:
            tmp = EC_KEY_new_by_curve_name(NID_secp521r1);
            break;
        default:
            log_err("Invalid arguments");
            goto err;
    }
    if (!tmp)
        goto err;

    if (*ecdh) {
        EC_KEY_free(*ecdh);
    }
    *ecdh = tmp;

    r = 1;

err:
    return r;
}
#else
int
init_ecdh(EVP_PKEY ** ecdh, int standardizedDomainParameters)
{
    int r = 0;
    EVP_PKEY * tmp = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM *params = NULL;
	OSSL_PARAM_BLD *bld = NULL;
    const char *curve = NULL;

    if (!ecdh) {
        log_err("Invalid arguments");
        return 0;
    }

    switch(standardizedDomainParameters) {
        case 8:
            /* NOTE: prime192v1 is equivalent to secp192r1 */
            curve = "prime192v1";
            break;
        case 9:
            curve = "brainpoolP192r1";
            break;
        case 10:
            curve = "secp224r1";
            break;
        case 11:
            curve = "brainpoolP224r1";
            break;
        case 12:
            /* NOTE: prime256v1 is equivalent to secp256r1 */
            curve = "prime256v1";
            break;
        case 13:
            curve = "brainpoolP256r1";
            break;
        case 14:
            curve = "brainpoolP320r1";
            break;
        case 15:
            curve = "secp384r1";
            break;
        case 16:
            curve = "brainpoolP384r1";
            break;
        case 17:
            curve = "brainpoolP512r1";
            break;
        case 18:
            curve = "secp521r1";
            break;
        default:
            log_err("Invalid arguments");
            goto err;
    }
    if (!tmp)
        goto err;

    if (!(bld = OSSL_PARAM_BLD_new())
            || !OSSL_PARAM_BLD_push_utf8_string(bld, "group", curve, strlen(curve))
            || !(params = OSSL_PARAM_BLD_to_param(bld))) {
        log_err("Cannot build OpenSSL params");
        goto err;
    }
    if (!(ctx = EVP_PKEY_CTX_new_from_name(0, "EC", 0))
            || !EVP_PKEY_fromdata_init(ctx)
            || !EVP_PKEY_fromdata(ctx, &tmp, EVP_PKEY_KEYPAIR, params)) {
        log_err("Cannot create EC key");
        goto err;
    }

    if (*ecdh) {
        EVP_PKEY_free(*ecdh);
    }
    *ecdh = tmp;

    r = 1;

err:
    OSSL_PARAM_BLD_free(bld);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(ctx);
    return r;
}
#endif


BUF_MEM *
ecdh_generate_key(EVP_PKEY *key, BN_CTX *bn_ctx)
{
    BUF_MEM *ret = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    check(key, "Invalid arguments");

    if (!(ctx = EVP_PKEY_CTX_new(key, NULL))
            || EVP_PKEY_keygen_init(ctx) <= 0
            || EVP_PKEY_keygen(ctx, &key) <= 0) {
        goto err;
    }

    /* The key agreement algorithm ECKA prevents small subgroup attacks by
     * using compatible cofactor multiplication. */
    ret = EVP_PKEY_pubkey2mem(key, bn_ctx);

err:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

BUF_MEM *
ecdh_compute_key(EVP_PKEY *key, const BUF_MEM * in, BN_CTX *bn_ctx)
{
    BUF_MEM *out = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L

    EC_POINT *ecp = NULL;
    EC_KEY *ecdh = NULL;
    const EC_GROUP *group = NULL;

    check((key && in), "Invalid arguments");

    ecdh = EVP_PKEY_get1_EC_KEY(key);
    if (!ecdh)
        return NULL;

    /* decode public key */
    group = EC_KEY_get0_group(ecdh);
    if (!group)
        goto err;
    ecp = EC_POINT_new(group);
    if (!ecp)
        goto err;
    if(!EC_POINT_oct2point(group, ecp, (unsigned char *) in->data, in->length,
            bn_ctx))
        goto err;

    /* get buffer in required size */
    out = BUF_MEM_create(EC_POINT_point2oct(group, ecp, EC_KEY_get_conv_form(ecdh),
            NULL, 0, bn_ctx));
    if (!out)
        goto err;

    /* copy data and set length */
    out->length = ECDH_compute_key(out->data, out->max, ecp, ecdh, NULL);
    if ((int) out->length < 0)
        goto err;

    EC_POINT_free(ecp);
    EC_KEY_free(ecdh);

    return out;

err:
    BUF_MEM_free(out);
    EC_POINT_free(ecp);
    EC_KEY_free(ecdh);

    return NULL;
#else
    EVP_PKEY *peerkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = 0;

    check((key && in), "Invalid arguments");

    if (!(ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL))
            || EVP_PKEY_derive_init(ctx) != 1
            || !(peerkey = EVP_PKEY_dup(key))) {
        goto err;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerkey) != 1
            || EVP_PKEY_derive(ctx, NULL, &len) != 1) {
        goto err;
    }

    /* get buffer in required size */
    out = BUF_MEM_create(len);
    if (!out)
        goto err;

    if (EVP_PKEY_derive(ctx, out->data, &out->length) != 1) {
        goto err;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerkey);
    return out;
err:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerkey);
    BUF_MEM_free(out);
    return NULL;
#endif
}
