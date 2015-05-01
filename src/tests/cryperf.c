/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/cryperf.c - Performance tests for various crypto primitives */
/*
 * Copyright (C) 2015 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/objects.h>

static krb5_context ctx;
static clock_t starttime;

static void
start()
{
    starttime = clock();
}

static void
stop(int iters, const char *msg1, const char *msg2)
{
    char *msg;
    clock_t elapsed = clock() - starttime;
    int nsec_per_iter = (long)elapsed * 1000 / iters;
    int usec_per_iter = (nsec_per_iter + 500) / 1000;

    assert(CLOCKS_PER_SEC == 1000000);

    if (asprintf(&msg, "%s%s%s", msg1, msg2 ? " " : "", msg2 ? msg2 : " ") < 0)
        abort();

    if (usec_per_iter == 0)
        printf("%-15s %5dns\n", msg, nsec_per_iter);
    else
        printf("%-15s %5dus\n", msg, usec_per_iter);
}

static void
test_aesenc(int iters)
{
    int i;
    krb5_keyblock k;
    char buf1[128], buf2[128];
    krb5_data in = empty_data(), out = make_data(buf2, sizeof(buf2));
    krb5_enc_data ctext;

    krb5_init_context(&ctx);
    krb5_c_make_random_key(ctx, ENCTYPE_AES256_CTS_HMAC_SHA1_96, &k);
    ctext.ciphertext = make_data(buf1, sizeof(buf1));
    for (i = 0; i <= iters; i++) {
        if (i == 1)
            start();
        krb5_c_encrypt(ctx, &k, 0, NULL, &in, &ctext);
        krb5_c_decrypt(ctx, &k, 0, NULL, &ctext, &out);
    }
    /* Give credit for twice the iterations since we encrypt and decrypt. */
    stop(iters * 2, "aesenc", NULL);
}

static void
test_aescksum(int iters)
{
    int i;
    krb5_keyblock k;
    krb5_data in = empty_data();
    krb5_checksum cksum;
    krb5_boolean valid;

    krb5_init_context(&ctx);
    krb5_c_make_random_key(ctx, ENCTYPE_AES256_CTS_HMAC_SHA1_96, &k);
    for (i = 0; i <= iters; i++) {
        if (i == 1)
            start();
        krb5_c_make_checksum(ctx, CKSUMTYPE_HMAC_SHA1_96_AES256, &k, 0, &in,
                             &cksum);
        krb5_c_verify_checksum(ctx, &k, 0, &in, &cksum, &valid);
        krb5_free_checksum_contents(ctx, &cksum);
    }
    /* Give credit for twice the iterations since we hash and verify. */
    stop(iters * 2, "aescksum", NULL);
}

static EC_GROUP *
get_group(const char *name)
{
    EC_GROUP *group = NULL;

    if (strcmp(name, "P-256") == 0)
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    else if (strcmp(name, "P-384") == 0)
        group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    else if (strcmp(name, "P-521") == 0)
        group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    assert(group != NULL);
    return group;
}

/* Test adding two random group elements. */
static void
test_ecadd(int iters, const char *name)
{
    EC_GROUP *group = get_group(name);
    EC_POINT *p1, *p2, *sum;
    BIGNUM *ord, *scalar1, *scalar2;
    BN_CTX *bnctx;
    int i;

    bnctx = BN_CTX_new();

    ord = BN_new();
    EC_GROUP_get_order(group, ord, bnctx);

    scalar1 = BN_new();
    BN_rand_range(scalar1, ord);
    p1 = EC_POINT_new(group);
    EC_POINT_mul(group, p1, scalar1, NULL, NULL, bnctx);

    scalar2 = BN_new();
    BN_rand_range(scalar2, ord);
    p2 = EC_POINT_new(group);
    EC_POINT_mul(group, p2, scalar2, NULL, NULL, bnctx);

    sum = EC_POINT_new(group);
    EC_POINT_add(group, sum, p1, p2, bnctx);
    start();
    for (i = 0; i < iters; i++)
        EC_POINT_add(group, sum, p1, p2, bnctx);
    stop(iters, "ecadd", name);
}

/* Test multiplying a group's generator by a random scalar. */
static void
test_ecmulg(int iters, const char *name)
{
    EC_GROUP *group = get_group(name);
    EC_POINT *product;
    BIGNUM *ord, *scalar;
    BN_CTX *bnctx;
    int i;

    bnctx = BN_CTX_new();
    EC_GROUP_precompute_mult(group, bnctx);

    ord = BN_new();
    EC_GROUP_get_order(group, ord, bnctx);

    scalar = BN_new();
    BN_rand_range(scalar, ord);

    product = EC_POINT_new(group);
    EC_POINT_mul(group, product, scalar, NULL, NULL, bnctx);
    start();
    for (i = 0; i < iters; i++)
        EC_POINT_mul(group, product, scalar, NULL, NULL, bnctx);
    stop(iters, "ecmulg", name);
}

/* Test multiplying a random group element by a random scalar. */
static void
test_ecmul(int iters, const char *name)
{
    EC_GROUP *group = get_group(name);
    EC_POINT *product, *p;
    BIGNUM *ord, *scalar;
    BN_CTX *bnctx;
    int i;

    bnctx = BN_CTX_new();
    EC_GROUP_precompute_mult(group, bnctx);

    ord = BN_new();
    EC_GROUP_get_order(group, ord, bnctx);

    scalar = BN_new();
    BN_rand_range(scalar, ord);

    p = EC_POINT_new(group);
    EC_POINT_mul(group, p, scalar, NULL, NULL, bnctx);
    product = EC_POINT_new(group);
    start();
    for (i = 0; i < iters; i++)
        EC_POINT_mul(group, product, NULL, p, scalar, bnctx);
    stop(iters, "ecmul", name);
}

/* Test multiplying a group's generator and a random element by a random
 * scalar, and adding the results. */
static void
test_ecmuladd(int iters, const char *name)
{
    EC_GROUP *group = get_group(name);
    EC_POINT *sumproduct, *p;
    BIGNUM *ord, *scalar;
    BN_CTX *bnctx;
    int i;

    bnctx = BN_CTX_new();
    EC_GROUP_precompute_mult(group, bnctx);

    ord = BN_new();
    EC_GROUP_get_order(group, ord, bnctx);

    scalar = BN_new();
    BN_rand_range(scalar, ord);

    p = EC_POINT_new(group);
    EC_POINT_mul(group, p, scalar, NULL, NULL, bnctx);
    sumproduct = EC_POINT_new(group);
    start();
    for (i = 0; i < iters; i++)
        EC_POINT_mul(group, sumproduct, scalar, p, scalar, bnctx);
    stop(iters, "ecmuladd", name);
}

/* Test multiplying a group's generator by a random scalar. */
static void
test_ecinvert(int iters, const char *name)
{
    EC_GROUP *group = get_group(name);
    EC_POINT *point;
    BIGNUM *ord, *scalar;
    BN_CTX *bnctx;
    int i;

    bnctx = BN_CTX_new();
    EC_GROUP_precompute_mult(group, bnctx);

    ord = BN_new();
    EC_GROUP_get_order(group, ord, bnctx);

    scalar = BN_new();
    BN_rand_range(scalar, ord);

    point = EC_POINT_new(group);
    EC_POINT_mul(group, point, scalar, NULL, NULL, bnctx);
    EC_POINT_invert(group, point, bnctx);
    start();
    for (i = 0; i < iters; i++)
        EC_POINT_invert(group, point, bnctx);
    stop(iters, "ecinvert", name);
}

/* Test multiplying a group's generator by a random scalar. */
static void
test_ecrecover(int iters, const char *name)
{
    EC_GROUP *group = get_group(name);
    EC_POINT *point;
    BIGNUM *ord, *x;
    BN_CTX *bnctx;
    int i;

    bnctx = BN_CTX_new();
    EC_GROUP_precompute_mult(group, bnctx);

    ord = BN_new();
    EC_GROUP_get_order(group, ord, bnctx);

    x = BN_new();
    BN_rand_range(x, ord);

    point = EC_POINT_new(group);
    EC_POINT_set_compressed_coordinates_GFp(group, point, x, 0, bnctx);
    start();
    for (i = 0; i < iters; i++)
        EC_POINT_set_compressed_coordinates_GFp(group, point, x, 0, bnctx);
    stop(iters, "ecrecover", name);
}

int curve25519_donna(uint8_t *, const uint8_t *, const uint8_t *);

/* Test curve25519 scalar multiplication using curve25519-donna.  (There's no
 * special optimization for multiplying by the generator.) */
static void
test_25519(int iters)
{
    static const uint8_t basepoint[32] = {9};
    uint8_t scalar[32], result[32];
    int fd, i;

    fd = open("/dev/urandom", O_RDONLY);
    assert(fd != -1);
    if (read(fd, scalar, 32) != 32)
        abort();
    close(fd);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    curve25519_donna(result, scalar, basepoint);
    start();
    for (i = 0; i < iters; i++)
        curve25519_donna(result, scalar, basepoint);
    stop(iters, "25519", NULL);
}

/* Test generating a 2048-bit DH public value. */
static void
test_dhgen(int iters)
{
    DH *privkey;
    int codes, i;

    privkey = DH_new();
    DH_generate_parameters_ex(privkey, 2048, DH_GENERATOR_2, NULL);
    DH_check(privkey, &codes);
    assert(codes == 0);
    DH_generate_key(privkey);
    start();
    for (i = 0; i < iters; i++)
        DH_generate_key(privkey);
    stop(iters, "dhgen", "2048");
}

/* Test computing a 2048-bit DH shared value. */
static void
test_dhcomp(int iters)
{
    DH *privkey;
    BIGNUM *pubkey = NULL;
    unsigned char *secret;
    int codes, i;

    privkey = DH_new();
    DH_generate_parameters_ex(privkey, 2048, DH_GENERATOR_2, NULL);
    DH_check(privkey, &codes);
    assert(codes == 0);
    DH_generate_key(privkey);

    BN_dec2bn(&pubkey, "01234567890123456789012345678901234567890123456789");
    secret = OPENSSL_malloc(DH_size(privkey));

    DH_compute_key(secret, pubkey, privkey);
    start();
    for (i = 0; i < iters; i++)
        DH_compute_key(secret, pubkey, privkey);
    stop(iters, "dhcomp", "2048");
}

int
main(int argc, char **argv)
{
    int iters;
    const char *op;

    if (argc == 1) {
        test_aesenc(100000);
        test_aescksum(100000);
        test_25519(100000);
        test_ecadd(100000, "P-256");
        test_ecmulg(10000, "P-256");
        test_ecmul(10000, "P-256");
        test_ecmuladd(10000, "P-256");
        test_ecinvert(100000, "P-256");
        test_ecrecover(10000, "P-256");
        test_ecadd(100000, "P-384");
        test_ecmulg(10000, "P-384");
        test_ecmul(10000, "P-384");
        test_ecmuladd(10000, "P-384");
        test_ecinvert(100000, "P-384");
        test_ecrecover(10000, "P-384");
        test_ecadd(100000, "P-521");
        test_ecmulg(10000, "P-521");
        test_ecmul(10000, "P-521");
        test_ecmuladd(10000, "P-521");
        test_ecinvert(100000, "P-521");
        test_ecrecover(10000, "P-521");
        test_dhgen(1000);
        test_dhcomp(1000);
        return 0;
    }

    assert(argc >= 3);
    iters = atoi(argv[1]);
    op = argv[2];

    if (strcmp(op, "aesenc") == 0)
        test_aesenc(iters);
    else if (strcmp(op, "aescksum") == 0)
        test_aescksum(iters);
    else if (strcmp(op, "ecadd") == 0)
        test_ecadd(iters, argv[3]);
    else if (strcmp(op, "ecmulg") == 0)
        test_ecmulg(iters, argv[3]);
    else if (strcmp(op, "ecmul") == 0)
        test_ecmul(iters, argv[3]);
    else if (strcmp(op, "ecmuladd") == 0)
        test_ecmuladd(iters, argv[3]);
    else if (strcmp(op, "ecinvert") == 0)
        test_ecinvert(iters, argv[3]);
    else if (strcmp(op, "ecrecover") == 0)
        test_ecrecover(iters, argv[3]);
    else if (strcmp(op, "25519") == 0)
        test_25519(iters);
    else if (strcmp(op, "dhgen") == 0)
        test_dhgen(iters);
    else if (strcmp(op, "dhcomp") == 0)
        test_dhcomp(iters);
    else
        abort();
    return 0;
}
