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
 * @file eac_dh.c
 * @brief Diffie Hellman helper functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_dh.h"
#include "eac_err.h"
#include "misc.h"
#include "ssl_compat.h"
#include <eac/eac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/param_build.h>
# include <openssl/core_names.h>
#endif

/**
 * @brief Public key validation method described in RFC 2631.
 *
 * Verify that DH->pub_key lies within the interval [2,p-1]. If it does not,
 * the key is invalid.
 * If DH->q exists, compute y^q mod p. If the result == 1, the key is valid.
 * Otherwise the key is invalid.
 *
 * @param[in] dh DH object to use
 * @param[in] ctx BN_CTX object
 * @param[out] ret Can contain these flags as result:
 * DH_CHECK_PUBKEY_TOO_SMALL (smaller than 2)
 * DH_CHECK_PUBKEY_TOO_LARGE (bigger than p-1)
 * DH_CHECK_PUBKEY_INVALID (y^q mod p != 1)
 *
 * @return 1 on success or 0 if an error occurred
 */
static int
DH_check_pub_key_rfc(EVP_PKEY *key, BN_CTX *ctx, int *ret);
#define DH_CHECK_PUBKEY_INVALID        0x04

#if OPENSSL_VERSION_NUMBER < 0x30000000L
int
init_dh(DH ** dh, int standardizedDomainParameters)
{
    int i;
    DH *tmp = NULL;

    check(dh, "Invalid arguments");

    if (!*dh) {
        switch (standardizedDomainParameters) {
           case 0:
              tmp = DH_get_1024_160();
              break;
           case 1:
              tmp = DH_get_2048_224();
              break;
           case 2:
              tmp = DH_get_2048_256();
              break;
           default:
              log_err("Invalid arguments");
              goto err;
        }
        if (!tmp)
            goto err;
    } else {
        /*Note: this could be something not matching standardizedDomainParameters */
        tmp = *dh;
    }

    if (!DH_check(tmp, &i))
        goto err;

    /* RFC 5114 parameters do not use safe primes and OpenSSL does not know
     * how to deal with generator other then 2 or 5. Therefore we have to
     * ignore some of the checks */
    i &= ~DH_CHECK_P_NOT_SAFE_PRIME;
    i &= ~DH_UNABLE_TO_CHECK_GENERATOR;

    check(!i, "Bad DH key");

    *dh = tmp;

    return 1;

err:
    if (tmp && !*dh) {
        DH_free(tmp);
    }

    return 0;
}
#else
int
init_dh(EVP_PKEY ** dh, int standardizedDomainParameters)
{
    int i;
    EVP_PKEY *tmp = NULL;
    const char *group = NULL;
    EVP_PKEY_CTX *check_ctx = NULL;

    check(dh, "Invalid arguments");

    if (!*dh) {
        OSSL_PARAM_BLD *param_bld = NULL;
        OSSL_PARAM *params = NULL;
        EVP_PKEY_CTX *ctx = NULL;

        switch (standardizedDomainParameters) {
           case 0:
              group = "dh_1024_160";
              break;
           case 1:
              group = "dh_2048_224";
              break;
           case 2:
              group = "dh_2048_256";
              break;
           default:
              log_err("Invalid arguments");
              goto err;
        }
        if (!group)
            goto err;

	    if (!(param_bld = OSSL_PARAM_BLD_new())
                || !OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", group, 0)
                || !(params = OSSL_PARAM_BLD_to_param(param_bld))) {
            check(0, "Building OSSL params failed");
            OSSL_PARAM_BLD_free(param_bld);
            goto err;
        }
        OSSL_PARAM_BLD_free(param_bld);
	    if (!(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL))
                || EVP_PKEY_fromdata_init(ctx) <= 0
                || EVP_PKEY_fromdata(ctx, &tmp, EVP_PKEY_KEYPAIR, params) <= 0) {
            check(0, "Cannot init DH key");
            OSSL_PARAM_free(params);
            EVP_PKEY_CTX_free(ctx);
            goto err;
        }
        OSSL_PARAM_free(params);
        EVP_PKEY_CTX_free(ctx);
    } else {
        /*Note: this could be something not matching standardizedDomainParameters */
        tmp = *dh;
    }

    check_ctx = EVP_PKEY_CTX_new(tmp, NULL);
    if (EVP_PKEY_param_check(check_ctx) <= 0) {
        /* RFC 5114 parameters do not use safe primes and OpenSSL does not know
        * how to deal with generator other then 2 or 5. Therefore we have to
        * ignore some of the checks.
        * Errors are stored on error stack. */
        unsigned int error;
        while((error = ERR_peek_error())) {
            if (error != DH_R_CHECK_P_NOT_SAFE_PRIME && error != DH_R_UNABLE_TO_CHECK_GENERATOR) {
                EVP_PKEY_CTX_free(check_ctx);
                check(error, "Bad DH key");
            }
            ERR_get_error(); // remove ignored error from queue
        }
    }
    EVP_PKEY_CTX_free(check_ctx);

    *dh = tmp;

    return 1;

err:
    if (tmp && !*dh) {
        EVP_PKEY_free(tmp);
    }

    return 0;
}
#endif

static int
DH_check_pub_key_rfc(EVP_PKEY *key, BN_CTX *ctx, int *ret)
{
    BIGNUM *bn = NULL;
    int ok = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    const BIGNUM *pub_key, *p, *q, *g;
#else
    BIGNUM *pub_key, *p, *q, *g;
    EVP_PKEY_CTX *pctx = NULL;
#endif
    DH *dh = NULL;

    check((dh && ret), "Invalid arguments");

    BN_CTX_start(ctx);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!(dh = EVP_PKEY_get1_DH(key)))
        goto err;
    DH_get0_key(dh, &pub_key, NULL);
    DH_get0_pqg(dh, &p, &q, &g);

    /* Verify that y lies within the interval [2,p-1]. */
    if (!DH_check_pub_key(dh, pub_key, ret))
        goto err;
#else
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_FFC_P, &p)
            || !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_FFC_Q, &q)
            || !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_FFC_G, &g)
            || !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PUB_KEY, &pub_key)) {
        goto err;
    }
    if (!(pctx = EVP_PKEY_CTX_new(key, NULL))
            || EVP_PKEY_public_check(pctx) <= 1)
        goto err;
#endif

    /* If the DH is conform to RFC 2631 it should have a non-NULL q.
     * Others (like the DHs generated from OpenSSL) might have a problem with
     * this check. */
    if (q) {
        /* Compute y^q mod p. If the result == 1, the key is valid. */
        bn = BN_CTX_get(ctx);
        if (!bn || !BN_mod_exp(bn, pub_key, q, p, ctx))
            goto err;
        if (!BN_is_one(bn))
            *ret |= DH_CHECK_PUBKEY_INVALID;
    }
    ok = 1;

err:
    BN_CTX_end(ctx);
    return ok;
}


#if OPENSSL_VERSION_NUMBER < 0x30000000L
BIGNUM *
DH_get_q(const DH *dh, BN_CTX *ctx)
#else
BIGNUM *
DH_get_q(const EVP_PKEY *dh, BN_CTX *ctx)
#endif
{
    BIGNUM *q_new = NULL, *bn = NULL;
    int i;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    const BIGNUM *p, *q;
#else
    BIGNUM *p = NULL, *q = NULL;
#endif

    check(dh, "Invalid arguments");

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    DH_get0_pqg(dh, &p, &q, NULL);
#else
    if (!EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_P, &p)
            || !EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_Q, &q)) {
        goto err;
    }
#endif
    if (!q) {
        q_new = BN_new();
        bn = BN_dup(p);

        /* DH primes should be strong, based on a Sophie Germain prime q
         * p=(2*q)+1 or (p-1)/2=q */
        if (!q_new || !bn ||
                !BN_sub_word(bn, 1) ||
                !BN_rshift1(q_new, bn)) {
            goto err;
        }
    } else {
        q_new = BN_dup(q);
    }

    /* q should always be prime */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    i = BN_is_prime_ex(q_new, BN_prime_checks, ctx, NULL);
#else
    i = BN_check_prime(q_new, ctx, NULL);
#endif
    if (i <= 0) {
       if (i == 0)
          log_err("Unable to get Sophie Germain prime");
       goto err;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BN_clear_free(p);
    BN_clear_free(q);
#endif

    return q_new;

err:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BN_clear_free(p);
    BN_clear_free(q);
#endif
    BN_clear_free(bn);
    BN_clear_free(q_new);

    return NULL;
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
BIGNUM *
DH_get_order(const DH *dh, BN_CTX *ctx)
#else
BIGNUM *
DH_get_order(const EVP_PKEY *dh, BN_CTX *ctx)
#endif
{
    BIGNUM *order = NULL, *bn = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    const BIGNUM *p, *g;
#else
    BIGNUM *p = NULL, *g = NULL;
#endif

    check(dh && ctx, "Invalid argument");

    BN_CTX_start(ctx);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    DH_get0_pqg(dh, &p, NULL, &g);
#else
    if (!EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_P, &p)
            || !EVP_PKEY_get_bn_param(dh, OSSL_PKEY_PARAM_FFC_G, &g)) {
        goto err;
    }
#endif
    /* suppose the order of g is q-1 */
    order = DH_get_q(dh, ctx);
    bn = BN_CTX_get(ctx);
    if (!bn || !order || !BN_sub_word(order, 1)
          || !BN_mod_exp(bn, g, order, p, ctx))
        goto err;

    if (BN_cmp(bn, BN_value_one()) != 0) {
        /* if bn != 1, then q-1 is not the order of g, but p-1 should be */
        if (!BN_sub(order, p, BN_value_one()) ||
              !BN_mod_exp(bn, g, order, p, ctx))
           goto err;
        check(BN_cmp(bn, BN_value_one()) == 0, "Unable to get order");
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BN_clear_free(p);
    BN_clear_free(g);
#endif

    BN_CTX_end(ctx);

    return order;

err:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BN_clear_free(p);
    BN_clear_free(g);
#endif
    BN_clear_free(order);
    BN_CTX_end(ctx);

    return NULL;
}

BUF_MEM *
dh_generate_key(EVP_PKEY *key, BN_CTX *bn_ctx)
{
    int suc;
    BUF_MEM *ret = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    const BIGNUM *pub_key;
#else
    BIGNUM *pub_key;
#endif
    EVP_PKEY_CTX *ctx = NULL;

    check(key, "Invalid arguments");

    if (!(ctx = EVP_PKEY_CTX_new(key, NULL))
            || EVP_PKEY_keygen_init(ctx) <= 0
            || EVP_PKEY_keygen(ctx, &key) <= 0) {
        goto err;
    }

    if (!DH_check_pub_key_rfc(key, bn_ctx, &suc))
        goto err;

    if (suc)
        goto err;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    DH_get0_key(dh, &pub_key, NULL);
#else
    EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PUB_KEY, &pub_key);
#endif

    ret = BN_bn2buf(pub_key);

err:
    EVP_PKEY_CTX_free(ctx);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    DH_free(dh);
#else
    BN_clear_free(pub_key);
#endif
    return ret;
}

BUF_MEM *
dh_compute_key(EVP_PKEY *key, const BUF_MEM * in, BN_CTX *bn_ctx)
{
    BUF_MEM *out = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    BIGNUM *bn = NULL;
    DH *dh = NULL;

    check(key && in, "Invalid arguments");

    dh = EVP_PKEY_get1_DH(key);
    if (!dh)
        return NULL;

    /* decode public key */
    bn = BN_bin2bn((unsigned char *) in->data, in->length, bn);
    if (!bn)
        goto err;

    out = BUF_MEM_create(DH_size(dh));
    if (!out)
        goto err;

    out->length = DH_compute_key((unsigned char *) out->data, bn, dh);
    if ((int) out->length < 0)
        goto err;

    BN_clear_free(bn);
    DH_free(dh);

    return out;

err:
    BUF_MEM_free(out);
    BN_clear_free(bn);
    DH_free(dh);

    return NULL;
#else
    EVP_PKEY *peerkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = 0;
#endif
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
DH *
DHparams_dup_with_q(DH *dh)
{
    const BIGNUM *p, *q, *g;

    DH *dup = DHparams_dup(dh);
    if (dup) {
        DH_get0_pqg(dh, &p, &q, &g);
        DH_set0_pqg(dup, BN_dup(p), BN_dup(q), BN_dup(g));
    }

    return dup;
}
#else
EVP_PKEY *
DHparams_dup_with_q(EVP_PKEY *dh)
{
    EVP_PKEY *dup = NULL;

    if (!(dup = EVP_PKEY_new())
            || EVP_PKEY_copy_parameters(dup, dh) != 1) {
        EVP_PKEY_free(dup);
        return NULL;
    }

    return dup;
}
#endif
