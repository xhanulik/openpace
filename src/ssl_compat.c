#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "eac_dh.h"
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <string.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/param_build.h>
# include <openssl/core_names.h>
#endif

#ifndef HAVE_DH_SET0_KEY
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    /* If the field pub_key in dh is NULL, the corresponding input
     * parameters MUST be non-NULL.  The priv_key field may
     * be left NULL.
     */
    if (dh->pub_key == NULL && pub_key == NULL)
        return 0;

    if (pub_key != NULL) {
        BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    return 1;
}
#endif

#ifndef HAVE_DH_GET0_KEY
void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = dh->pub_key;
    if (priv_key != NULL)
        *priv_key = dh->priv_key;
}
#endif

#ifndef HAVE_DH_GET0_PQG
void DH_get0_pqg(const DH *dh,
        const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
        *p = dh->p;
    if (q != NULL)
        *q = dh->q;
    if (g != NULL)
        *g = dh->g;
}
#endif

#ifndef HAVE_DH_SET0_PQG
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->p == NULL && p == NULL)
            || (dh->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(dh->p);
        dh->p = p;
    }
    if (q != NULL) {
        BN_free(dh->q);
        dh->q = q;
    }
    if (g != NULL) {
        BN_free(dh->g);
        dh->g = g;
    }

    if (q != NULL) {
        dh->length = BN_num_bits(q);
    }

    return 1;
}
#endif

#ifndef HAVE_RSA_SET0_KEY
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
            || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}
#endif

#ifndef HAVE_RSA_GET0_KEY
void RSA_get0_key(const RSA *r,
        const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}
#endif

#ifndef HAVE_ECDSA_SIG_SET0
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}
#endif

#ifndef HAVE_ECDSA_SIG_GET0
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL)
        *pr = sig->r;
    if (ps != NULL)
        *ps = sig->s;
}
#endif

#ifndef HAVE_ASN1_STRING_GET0_DATA
const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x)
{
    return x->data;
}
#endif

#if !defined(HAVE_DECL_OPENSSL_ZALLOC) || HAVE_DECL_OPENSSL_ZALLOC == 0
void *OPENSSL_zalloc(size_t num)
{
    void *out = OPENSSL_malloc(num);

    if (out != NULL)
        memset(out, 0, num);

    return out;
}
#endif

#ifndef HAVE_EC_POINT_GET_AFFINE_COORDINATES
int EC_POINT_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{
    return EC_POINT_get_affine_coordinates_GF2m(group, p, x, y, ctx);
}
#endif

#ifndef HAVE_EC_POINT_SET_AFFINE_COORDINATES
int EC_POINT_set_affine_coordinates(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)
{
    return EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
}
#endif

#ifndef HAVE_EVP_PKEY_DUP
EVP_PKEY *
EVP_PKEY_dup(EVP_PKEY *key)
{
    EVP_PKEY *out = NULL;
    DH *dh_in = NULL, *dh_out = NULL;
    EC_KEY *ec_in = NULL, *ec_out = NULL;
    RSA *rsa_in = NULL, *rsa_out = NULL;

    out = EVP_PKEY_new();

    if (!key || !out)
        goto err;

    switch (EVP_PKEY_base_id(key)) {
        case EVP_PKEY_DH:
        case EVP_PKEY_DHX:
            dh_in = EVP_PKEY_get1_DH(key);
            if (!dh_in)
                goto err;

            dh_out = DHparams_dup_with_q(dh_in);
            if (!dh_out)
                goto err;

            EVP_PKEY_set1_DH(out, dh_out);
            DH_free(dh_out);
            DH_free(dh_in);
            break;

        case EVP_PKEY_EC:
            ec_in = EVP_PKEY_get1_EC_KEY(key);
            if (!ec_in)
                goto err;

            ec_out = EC_KEY_dup(ec_in);
            if (!ec_out)
                goto err;

            EVP_PKEY_set1_EC_KEY(out, ec_out);
            EC_KEY_free(ec_out);
            EC_KEY_free(ec_in);
            break;

        case EVP_PKEY_RSA:
            rsa_in = EVP_PKEY_get1_RSA(key);
            if (!rsa_in)
                goto err;

            rsa_out = RSAPrivateKey_dup(rsa_in);
            if (!rsa_out)
                goto err;

            EVP_PKEY_set1_RSA(out, rsa_out);
            RSA_free(rsa_out);
            RSA_free(rsa_in);
            break;

        default:
            goto err;
    }

    return out;

err:
    if (dh_in)
        DH_free(dh_in);
    if (ec_in)
        EC_KEY_free(ec_in);
    if (rsa_in)
        RSA_free(rsa_in);
    if (out)
        EVP_PKEY_free(out);

    return NULL;
}
#endif

#ifndef HAVE_EC_GROUP_to_params
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
OSSL_PARAM *EC_GROUP_to_params(const EC_GROUP *group, OSSL_LIB_CTX *libctx,
                               const char *propq, BN_CTX *bnctx)
{
    OSSL_PARAM_BLD *bld = NULL;
    BN_CTX *new_bnctx = NULL;
    OSSL_PARAM *params = NULL;
    int conv_form = 0, encoding_flag = 0, curve_nid = NID_undef;
    const char *conv_form_name = NULL, *encoding_name = NULL;
    unsigned char *gen_buf = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;

    if (group == NULL)
        goto err;

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        goto err;

    if (bnctx == NULL)
        bnctx = new_bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL)
        goto err;
    BN_CTX_start(bnctx);

    /* get conversion format */
    conv_form = EC_GROUP_get_point_conversion_form(group);
    switch(conv_form) {
        case POINT_CONVERSION_UNCOMPRESSED:
            conv_form_name = "uncompressed";
            break;
        case POINT_CONVERSION_COMPRESSED:
            conv_form_name = "compressed";
            break;
        case POINT_CONVERSION_HYBRID:
            conv_form_name = "hybrid";
            break;
        default:
            goto err;
    }
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                conv_form_name, sizeof(conv_form_name))) {
        goto err;
    }

    /* get encoding of curve */
    encoding_flag = EC_GROUP_get_asn1_flag(group) & OPENSSL_EC_NAMED_CURVE;
    encoding_name = encoding_flag == OPENSSL_EC_EXPLICIT_CURVE ? "explicit" : "named_curve";
    if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_ENCODING, encoding_name,
                sizeof(encoding_name))) {
        goto err;
    }

    /* decoded from specific params missing */
    /* nid */
    curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid != NID_undef) {
        /* named curve */
        const char *curve_name = OSSL_EC_curve_nid2name(curve_nid);
        if (!curve_name || !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                    curve_name, sizeof(curve_name))) {
            goto err;
        }
    } else {
        /* explicit to data */
        int fid = 0;
        const BIGNUM *order = NULL, *cofactor = NULL;
        unsigned char *seed = NULL;
        const char *field_type = SN_X9_62_prime_field;
        size_t seed_len = 0, genbuf_len = 0;
        const EC_POINT *genpt = NULL;

        /* get fid */
        fid = EC_GROUP_get_field_type(group);
        if (fid == NID_X9_62_characteristic_two_field) {
#ifdef OPENSSL_NO_EC2M
            goto err;
#else
            field_type = SN_X9_62_characteristic_two_field;
#endif
        } else {
            goto err;
        }
        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_FIELD_TYPE,
                    field_type, sizeof(field_type))) {
            goto err;
        }

        /* get p, a, b */
        if (!(p = BN_CTX_get(bnctx))
                || !(a = BN_CTX_get(bnctx))
                || !(b = BN_CTX_get(bnctx))
                || !EC_GROUP_get_curve(group, p, a, b, bnctx)
                || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_P, p)
                || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_A, a)
                || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_B, b)) {
            goto err;
        }

        /* order */
        order = EC_GROUP_get0_order(group);
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_ORDER, order)) {
            goto err;
        }

        /* generator */
        genpt = EC_GROUP_get0_generator(group);
        genbuf_len = EC_POINT_point2buf(group, genpt, conv_form, &gen_buf, bnctx);
        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_GENERATOR, gen_buf, genbuf_len)) {
            goto err;
        }

        /* cofactor */
        cofactor = EC_GROUP_get0_cofactor(group);
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_EC_COFACTOR, cofactor)) {
            goto err;
        }

        /* seed */
        seed = EC_GROUP_get0_seed(group);
        seed_len = EC_GROUP_get_seed_len(group);
        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_EC_SEED, seed, seed_len)) {
            goto err;
        }
    }

    params = OSSL_PARAM_BLD_to_param(bld);

 err:
    BN_free(p);
    BN_free(a);
    BN_free(b);
    OSSL_PARAM_BLD_free(bld);
    OPENSSL_free(gen_buf);
    BN_CTX_end(bnctx);
    BN_CTX_free(new_bnctx);
    return params;
}
#endif
#endif
