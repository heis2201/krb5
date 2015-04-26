/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/mk_rep.c */
/*
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */
/*
 * Copyright (c) 2006-2008, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"
#include "int-proto.h"
#include "auth_con.h"

int k5_curve25519_donna(uint8_t *, const uint8_t *, const uint8_t *);
static const uint8_t basepoint[32] = {9};

static krb5_error_code
generate_x25519_key(krb5_context context, krb5_auth_context auth_context,
                    uint8_t *pub_out)
{
    krb5_error_code ret;
    uint8_t pvt[32], shared[32];
    krb5_data d;
    krb5_keyblock kb;
    size_t keylen;

    d = make_data(pvt, 32);
    ret = krb5_c_random_make_octets(context, &d);
    if (ret)
        return ret;
    pvt[0] &= 248;
    pvt[31] &= 127;
    pvt[31] |= 64;

    k5_curve25519_donna(shared, pvt, auth_context->x25519);

    /* XXX should hash the result or PRF+ the existing key */
    kb.magic = KV5M_KEYBLOCK;
    kb.enctype = auth_context->negotiated_etype;
    ret = krb5_c_keylengths(context, kb.enctype, NULL, &keylen);
    if (ret)
        return ret;
    kb.length = keylen;
    kb.contents = shared;

    ret = krb5_auth_con_setsendsubkey(context, auth_context, &kb);
    if (ret)
        return ret;
    ret = krb5_auth_con_setrecvsubkey(context, auth_context, &kb);
    if (ret) {
        (void)krb5_auth_con_setsendsubkey(context, auth_context, NULL);
        return ret;
    }

    k5_curve25519_donna(pub_out, pvt, basepoint);
    return 0;
}

/*
  Formats a KRB_AP_REP message into outbuf.

  The outbuf buffer storage is allocated, and should be freed by the
  caller when finished.

  returns system errors
*/

static krb5_error_code
k5_mk_rep(krb5_context context, krb5_auth_context auth_context,
          krb5_data *outbuf, int dce_style)
{
    krb5_error_code       retval;
    krb5_ap_rep_enc_part  repl;
    krb5_ap_rep           reply;
    krb5_data           * scratch;
    krb5_data           * toutbuf;
    uint8_t               x25519pub[38];
    krb5_keyblock         x25519k;

    /* Make the reply */
    if (((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) ||
         (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE)) &&
        (auth_context->local_seq_number == 0)) {
        if ((retval = krb5_generate_seq_number(context,
                                               &auth_context->key->keyblock,
                                               &auth_context->local_seq_number)))
            return(retval);
    }

    if (dce_style) {
        krb5_us_timeofday(context, &repl.ctime, &repl.cusec);
    } else {
        repl.ctime = auth_context->authentp->ctime;
        repl.cusec = auth_context->authentp->cusec;
    }

    if (dce_style) {
        repl.subkey = NULL;
    } else if (auth_context->x25519_set) {
        retval = generate_x25519_key(context, auth_context, x25519pub + 6);
        if (retval)
            return retval;
        /* XXX awful dirty hack */
        memcpy(x25519pub, "X25519", 6);
        x25519k.magic = KV5M_KEYBLOCK;
        x25519k.enctype = auth_context->negotiated_etype;
        x25519k.length = 38;
        x25519k.contents = x25519pub;
        repl.subkey = &x25519k;
    } else if (auth_context->auth_context_flags &
               KRB5_AUTH_CONTEXT_USE_SUBKEY) {
        assert(auth_context->negotiated_etype != ENCTYPE_NULL);

        retval = k5_generate_and_save_subkey(context, auth_context,
                                             &auth_context->key->keyblock,
                                             auth_context->negotiated_etype);
        if (retval)
            return retval;
        repl.subkey = &auth_context->send_subkey->keyblock;
    } else
        repl.subkey = auth_context->authentp->subkey;

    if (dce_style)
        repl.seq_number = auth_context->remote_seq_number;
    else
        repl.seq_number = auth_context->local_seq_number;

    TRACE_MK_REP(context, repl.ctime, repl.cusec, repl.subkey,
                 repl.seq_number);

    /* encode it before encrypting */
    if ((retval = encode_krb5_ap_rep_enc_part(&repl, &scratch)))
        return retval;

    if ((retval = k5_encrypt_keyhelper(context, auth_context->key,
                                       KRB5_KEYUSAGE_AP_REP_ENCPART, scratch,
                                       &reply.enc_part)))
        goto cleanup_scratch;

    if (!(retval = encode_krb5_ap_rep(&reply, &toutbuf))) {
        *outbuf = *toutbuf;
        free(toutbuf);
    }

    memset(reply.enc_part.ciphertext.data, 0, reply.enc_part.ciphertext.length);
    free(reply.enc_part.ciphertext.data);
    reply.enc_part.ciphertext.length = 0;
    reply.enc_part.ciphertext.data = 0;

cleanup_scratch:
    memset(scratch->data, 0, scratch->length);
    krb5_free_data(context, scratch);

    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_mk_rep(krb5_context context, krb5_auth_context auth_context, krb5_data *outbuf)
{
    return k5_mk_rep(context, auth_context, outbuf, 0);
}

krb5_error_code KRB5_CALLCONV
krb5_mk_rep_dce(krb5_context context, krb5_auth_context auth_context, krb5_data *outbuf)
{
    return k5_mk_rep(context, auth_context, outbuf, 1);
}
