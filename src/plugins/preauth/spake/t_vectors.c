/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/spake/t_vectors.c - SPAKE test vector verification */
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
#include "groups.h"
#include "iana.h"
#include "util.h"
#include <ctype.h>

struct test {
    krb5_enctype enctype;
    int32_t group;
    const char *ikey;
    const char *x;
    const char *y;
    const char *T;
    const char *S;
    const char *K;
    const char *ochal;
    const char *support;
    const char *challenge;
    const char *tcksum;
    const char *body;
    const char *K0;
    const char *K1;
    const char *K2;
    const char *K3;
} tests[] = {
    { ENCTYPE_DES3_CBC_SHA1, SPAKE_GROUP_P256,
      /* w: 686D84730CB8679AE95416C6567C6A63F2C9CEF124F7A3371AE81E11CAD42A37 */
      /* initial key, x, y, T, S, K */
      "850BB51358548CD05E86768C313E3BFEF7511937DCF72C3E",
      "7A024204F7C1BD874DA5E709D4713D60C8A70639EB1167B367A9C3787C65C1E5",
      "6F25E2A25A92118719C78DF48F4FF31E78DE58575487CE1EAF19922AD9B8A714",
      "0348E842159DB7F3ABD886C8C8F8D5A4AA44A9D5FE01DC7C601C557BB9ECC1C778",
      "034894316BB8896A0C4E74B720E864F76CAAAD71AF811027FABE1E918FA9111471",
      "03DA7EC21E5120243C19E715232D30E1E2B131D206E023091F4147715C88536DF2",
      /* ochal, support, challenge, tcksum, body */
      NULL,
      "A0093007A0053003020101",
      "A1373035A003020101A12304210348E842159DB7F3ABD886C8C8F8D5A4AA44A9D5FE01"
      "DC7C601C557BB9ECC1C778A20930073005A003020101",
      "4723A22F03412C121E7409BB01DBD4CEC09D464C",
      "3075A00703050000000000A1143012A003020101A10B30091B077261656275726EA210"
      "1B0E415448454E412E4D49542E454455A3233021A003020102A11A30181B066B726274"
      "67741B0E415448454E412E4D49542E454455A511180F31393730303130313030303030"
      "305AA703020100A8053003020110",
      /* K'[0], K'[1], K'[2], K'[3] */
      "3E108619169476A19BB5CDDCC408805768F82FA110F82586",
      "FE8307014932323D974ABF4037F4FD08161A01D37C577985",
      "BC6154A8922A4C91AD76B9FEA7CDC868D0C815D9161675C8",
      "E076A8A73B6E62F41F194045076713A4A2B319A8EA8358D0"
    },

    { ENCTYPE_ARCFOUR_HMAC, SPAKE_GROUP_P256,
      /* w: 7C86659D29CF2B2EA93BFE79C3CEFB8850E82215B3EA6FCD896561D48048F49C */
      /* initial key, x, y, T, S, K */
      "8846F7EAEE8FB117AD06BDD830B7586C",
      "03983CA8EA7E9D498C778EA6EB2083E6CE164DBA0FF18E0242AF9FC385776E9A",
      "A0116BE5AB0C1681C8F8E3D0D3290A4CB5D32B1666194CB1D71037D1B83E90EC",
      "03C55D4BA6BDF9F8204F4784F74FE2146E3CC8C71323191904C2A7DC36640258CC",
      "0298C5D75E75A88B0CA7AF1C691698137569D3CBB40B80CB841257DE87B5867E29",
      "030008D1317C319B987123256A5293596549241C6CFFBFF5CD79BE5A4A13FED9CB",
      /* ochal, support, challenge, tcksum, body */
      NULL,
      "A0093007A0053003020101",
      "A1373035A003020101A123042103C55D4BA6BDF9F8204F4784F74FE2146E3CC8C71323"
      "191904C2A7DC36640258CCA20930073005A003020101",
      "0826A7238207CD4ED45D55382BE408ED",
      "3075A00703050000000000A1143012A003020101A10B30091B077261656275726EA210"
      "1B0E415448454E412E4D49542E454455A3233021A003020102A11A30181B066B726274"
      "67741B0E415448454E412E4D49542E454455A511180F31393730303130313030303030"
      "305AA703020100A8053003020117",
      /* K'[0], K'[1], K'[2], K'[3] */
      "D909B840C43A6FAB613F0BA94B8360D2",
      "DE6EB6E597A194F2B5EE19E9A7A25DC0",
      "65B7379944D04E4DEA0EC946E169516B",
      "3FD740593E47AB91A03496C20DC60351"
    },

    { ENCTYPE_AES128_CTS_HMAC_SHA1_96, SPAKE_GROUP_P256,
      /* w: 0D591B197B667E083C2F5F98AC891D3C9F99E710E464E62F1FB7C9B67936F3EB */
      /* initial key, x, y, T, S, K */
      "FCA822951813FB252154C883F5EE1CF4",
      "CC45782198A6416D1775336D71EACD0549A3E80E966E12778C1745A79A6A5F92",
      "2FCD81B5D24BACE4307BF3262F1205544A5308CC3DFABC08935DDD725129FB7C",
      "03B74800A26367EB7D85FF65A43795EB7819ED2A6316F4D8BAAFC6E0FACAA3D4AC",
      "0295516D00C1B08C9C9FC898AD104AEA0E50E78048DFB31FE4D0D9FA7EAEFCAA01",
      "02041A9B3FEFF3CDCD8C7E3BB9C486574FC43A7DB7CC5B89B7D39AA062D7A96BC9",
      /* ochal, support, challenge, tcksum, body */
      NULL,
      "A0093007A0053003020101",
      "A1373035A003020101A123042103B74800A26367EB7D85FF65A43795EB7819ED2A6316"
      "F4D8BAAFC6E0FACAA3D4ACA20930073005A003020101",
      "100B390284EB6186F8075565",
      "3075A00703050000000000A1143012A003020101A10B30091B077261656275726EA210"
      "1B0E415448454E412E4D49542E454455A3233021A003020102A11A30181B066B726274"
      "67741B0E415448454E412E4D49542E454455A511180F31393730303130313030303030"
      "305AA703020100A8053003020111",
      /* K'[0], K'[1], K'[2], K'[3] */
      "C3F244D19E86C6ACF11AD95ABD843245",
      "938A6C386DD8AA2791FB7C074463C571",
      "FE26C7467FB75126FC7866933D4E4972",
      "ACB2847BA8381B116E4559472A0BE344"
    },
    { ENCTYPE_AES256_CTS_HMAC_SHA1_96, SPAKE_GROUP_P256,
      /* w: E902341590A1B4BB4D606A1C643CCCB3F2108F1B6AA97B381012B9400C9E3F4E */
      /* initial key, x, y, T, S, K */
      "01B897121D933AB44B47EB5494DB15E50EB74530DBDAE9B634D65020FF5D88C1",
      "864A7A50B48D73F1D67E55FD642BFA42AEF9C00B8A64C1B9D450FE4AEC4F217B",
      "9CDF5A865306F3F5151665705B7C709ACB175A5AFB82860DEABCA8D0B341FACD",
      "0250967D9797E875F57D940B0E2F9E153E4F1DA1001A0F0C5794242AA36DC135E9",
      "03CCD2688B5860CBD9BBC6B1FB5B71FBD6C6C958DE59DA4C941EF7867BDC7E6577",
      "02D623EB8BF59166555E6818BA95A51FF298019DFD600329CE269B85FBB248B439",
      /* ochal, support, challenge, tcksum, body */
      NULL,
      "A0093007A0053003020101",
      "A1373035A003020101A12304210250967D9797E875F57D940B0E2F9E153E4F1DA1001A"
      "0F0C5794242AA36DC135E9A20930073005A003020101",
      "7094A670B3823D3C65879BDF",
      "3075A00703050000000000A1143012A003020101A10B30091B077261656275726EA210"
      "1B0E415448454E412E4D49542E454455A3233021A003020102A11A30181B066B726274"
      "67741B0E415448454E412E4D49542E454455A511180F31393730303130313030303030"
      "305AA703020100A8053003020112",
      /* K'[0], K'[1], K'[2], K'[3] */
      "040D16460337B29B31FA9E71802DCC2380965F4F5471DAB77C0DDCDE5420C09F",
      "475EA6D972FFD4621697804E4FD1DD793F089039A38624BB605A7E1092D93796",
      "1360738666FC3D87B01183B90BE4C23233E086563C162C11645E9A4C692FB0D3",
      "71172BF813AEB0A6FE967D330EB80F997BE027D0533F5FC9F74B4F4116753992"
    },

    /* Successful optimistic challenge (no support message in transcript) */
    { ENCTYPE_AES128_CTS_HMAC_SHA1_96, SPAKE_GROUP_P256,
      /* w: 0D591B197B667E083C2F5F98AC891D3C9F99E710E464E62F1FB7C9B67936F3EB */
      /* initial key, x, y, T, S, K */
      "FCA822951813FB252154C883F5EE1CF4",
      "1FB797FAB7D6467B2F5A522AF87F43FDF606254131D0B6640589F8779B025244",
      "8B53031D05D51433ADE9B2B4EFDD35F80FA34266CCFDBA9BBA26D85135E8579A",
      "0376631D8B8A7E1836892A76B0AE565C5BC398705263359B77995BE097D05D2004",
      "03F893E231067BC64E21248D6BF83C4C156FA7506579CD1FD1A7243BC7989AAAAC",
      "03DA7902D8A0C28A748E6FF9C2EB95673D889642CB66FE0E2CED05D4089AD99F56",
      /* ochal, support, challenge, tcksum, body */
      NULL,
      NULL,
      "A1373035A003020101A12304210376631D8B8A7E1836892A76B0AE565C5BC398705263"
      "359B77995BE097D05D2004A20930073005A003020101",
      "CFD4190A01FA44297C5A62E2",
      "3075A00703050000000000A1143012A003020101A10B30091B077261656275726EA210"
      "1B0E415448454E412E4D49542E454455A3233021A003020102A11A30181B066B726274"
      "67741B0E415448454E412E4D49542E454455A511180F31393730303130313030303030"
      "305AA703020100A8053003020111",
      /* K'[0], K'[1], K'[2], K'[3] */
      "35E8C79780573313CF780145FC0D9E5B",
      "2116CDEE5100AFAF39641D274F205E86",
      "CF1EF16F831E4CB8D142BC177E72CFDD",
      "068ABFF25236CC5CDC3FC414D86F96E7"
    },
};

static krb5_context ctx;

static void
check(krb5_error_code code)
{
    const char *errmsg;

    if (code) {
        errmsg = krb5_get_error_message(ctx, code);
        assert(errmsg != NULL);
        abort();
    }
}

static void
check_key_equal(const krb5_keyblock *kb1, const krb5_keyblock *kb2)
{
    assert(kb1->enctype == kb2->enctype);
    assert(kb1->length == kb2->length);
    assert(memcmp(kb1->contents, kb2->contents, kb1->length) == 0);
}

static int
decode_hexchar(unsigned char c)
{
    if (isdigit(c))
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    abort();
}

static krb5_data *
decode_data(const char *s)
{
    size_t len = strlen(s), i;
    char *b;
    krb5_data *d;

    assert(len % 2 == 0);
    b = malloc(len / 2);
    assert(b != NULL);
    for (i = 0; i < len / 2; i++)
        b[i] = decode_hexchar(s[i * 2]) * 16 + decode_hexchar(s[i * 2 + 1]);
    d = malloc(sizeof(*d));
    assert(d != NULL);
    *d = make_data(b, len / 2);
    return d;
}

static krb5_keyblock *
decode_keyblock(krb5_enctype enctype, const char *s)
{
    krb5_data *d;
    krb5_keyblock *kb;

    d = decode_data(s);
    kb = malloc(sizeof(*kb));
    kb->magic = KV5M_KEYBLOCK;
    kb->enctype = enctype;
    kb->length = d->length;
    kb->contents = (uint8_t *)d->data;
    free(d);
    return kb;
}

static void
run_test(const struct test *t)
{
    groupstate *gstate;
    krb5_keyblock *ikey, *K0, *K1, *K2, *K3, *kb;
    krb5_data *x, *y, *T, *S, *K, *ochal, *support, *challenge, *tcksum, *body;
    krb5_data result, cksum;

    /* Decode hex strings into keyblocks and byte strings. */
    ikey = decode_keyblock(t->enctype, t->ikey);
    x = decode_data(t->x);
    y = decode_data(t->y);
    T = decode_data(t->T);
    S = decode_data(t->S);
    K = decode_data(t->K);
    ochal = (t->ochal != NULL) ? decode_data(t->ochal) : NULL;
    support = (t->support != NULL) ? decode_data(t->support) : NULL;
    challenge = decode_data(t->challenge);
    tcksum = decode_data(t->tcksum);
    body = decode_data(t->body);
    K0 = decode_keyblock(t->enctype, t->K0);
    K1 = decode_keyblock(t->enctype, t->K1);
    K2 = decode_keyblock(t->enctype, t->K2);
    K3 = decode_keyblock(t->enctype, t->K3);

    /* Verify KDC-side result computation. */
    check(group_init_state(ctx, TRUE, &gstate));
    check(group_result(ctx, gstate, t->group, ikey, x, S, &result));
    assert(data_eq(*K, result));
    krb5_free_data_contents(ctx, &result);
    group_free_state(gstate);

    /* Verify client-side result computation. */
    check(group_init_state(ctx, FALSE, &gstate));
    check(group_result(ctx, gstate, t->group, ikey, y, T, &result));
    assert(data_eq(*K, result));
    krb5_free_data_contents(ctx, &result);
    group_free_state(gstate);

    /* Verify transcript checksum. */
    cksum = empty_data();
    if (ochal != NULL)
        check(update_tcksum(ctx, &cksum, ikey, ochal));
    if (support != NULL)
        check(update_tcksum(ctx, &cksum, ikey, support));
    check(update_tcksum(ctx, &cksum, ikey, challenge));
    check(update_tcksum(ctx, &cksum, ikey, S));
    assert(data_eq(*tcksum, cksum));
    krb5_free_data_contents(ctx, &cksum);

    /* Verify derived keys. */
    check(derive_key(ctx, t->group, ikey, K, tcksum, body, 0, &kb));
    check_key_equal(K0, kb);
    krb5_free_keyblock(ctx, kb);
    check(derive_key(ctx, t->group, ikey, K, tcksum, body, 1, &kb));
    check_key_equal(K1, kb);
    krb5_free_keyblock(ctx, kb);
    check(derive_key(ctx, t->group, ikey, K, tcksum, body, 2, &kb));
    check_key_equal(K2, kb);
    krb5_free_keyblock(ctx, kb);
    check(derive_key(ctx, t->group, ikey, K, tcksum, body, 3, &kb));
    check_key_equal(K3, kb);
    krb5_free_keyblock(ctx, kb);

    krb5_free_keyblock(ctx, ikey);
    krb5_free_data(ctx, x);
    krb5_free_data(ctx, y);
    krb5_free_data(ctx, T);
    krb5_free_data(ctx, S);
    krb5_free_data(ctx, K);
    krb5_free_data(ctx, ochal);
    krb5_free_data(ctx, support);
    krb5_free_data(ctx, challenge);
    krb5_free_data(ctx, tcksum);
    krb5_free_data(ctx, body);
    krb5_free_keyblock(ctx, K0);
    krb5_free_keyblock(ctx, K1);
    krb5_free_keyblock(ctx, K2);
    krb5_free_keyblock(ctx, K3);
}

int
main()
{
    size_t i;

    check(krb5_init_context(&ctx));
    for (i = 0; i < sizeof(tests) / sizeof(*tests); i++)
        run_test(&tests[i]);
    krb5_free_context(ctx);
    return 0;
}
