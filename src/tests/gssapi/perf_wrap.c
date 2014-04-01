/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/gssapi/perf_wrap.c - Performance harness for gss_wrap/unwrap */
/*
 * Copyright (C) 2014 by the Massachusetts Institute of Technology.
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

#include <stdio.h>
#include "common.h"
#include <sys/time.h>

int
main(int argc, char **argv)
{
    OM_uint32 minor, flags;
    gss_OID mech = &mech_krb5;
    gss_name_t tname;
    gss_ctx_id_t ictx, actx;
    int i, count;
    size_t payload_size;
    gss_buffer_desc plain, ctext;
    krb5_context context;
    krb5_data d;
    char *pbuf;
    void *lptr;
    gss_krb5_lucid_context_v1_t *lctx;
    krb5_enctype etype;
    char ename[64];
    struct timeval start_time, end_time;
    double difftime, rate;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s target iterations payload-size\n", argv[0]);
        exit(1);
    }
    tname = import_name(argv[1]);
    count = atoi(argv[2]);
    payload_size = atol(argv[3]);

    flags = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_MUTUAL_FLAG;
    establish_contexts(mech, GSS_C_NO_CREDENTIAL, GSS_C_NO_CREDENTIAL, tname,
                       flags, &ictx, &actx, NULL, NULL, NULL);

    /* Construct a random plaintext block. */
    pbuf = malloc(payload_size);
    if (pbuf == NULL)
        abort();
    check_k5err(NULL, "krb5_init_context", krb5_init_context(&context));
    d.data = pbuf;
    d.length = payload_size;
    check_k5err(context, "krb5_c_random_make_octets",
                krb5_c_random_make_octets(context, &d));
    plain.value = pbuf;
    plain.length = payload_size;

    (void)gettimeofday(&start_time, NULL);
    for (i = 0; i < count; i++) {
        (void)gss_wrap(&minor, ictx, 1, GSS_C_QOP_DEFAULT, &plain, NULL,
                       &ctext);
        (void)gss_release_buffer(&minor, &ctext);
    }
    (void)gettimeofday(&end_time, NULL);

    /* Find out the enctype by exporting ictx to a lucid sec context.  (This
     * destroys ictx.) */
    (void)gss_krb5_export_lucid_sec_context(&minor, &ictx, 1, &lptr);
    lctx = lptr;
    etype = lctx->protocol ? (lctx->cfx_kd.have_acceptor_subkey ?
                              lctx->cfx_kd.acceptor_subkey.type :
                              lctx->cfx_kd.ctx_key.type) :
        lctx->rfc1964_kd.ctx_key.type;
    check_k5err(context, "krb5_enctype_to_name",
                krb5_enctype_to_name(etype, TRUE, ename, sizeof(ename)));

    difftime = end_time.tv_sec - start_time.tv_sec +
        (double)(end_time.tv_usec - start_time.tv_usec) / 1000000;
    rate = (double)payload_size * count / (1024 * 1024) / difftime;
    printf("%s, payload size %d: %.1f MB/sec\n", ename, (int)payload_size,
           rate);

    free(pbuf);
    (void)gss_release_name(&minor, &tname);
    (void)gss_krb5_free_lucid_sec_context(&minor, lptr);
    (void)gss_delete_sec_context(&minor, &actx, NULL);
    krb5_free_context(context);
    return 0;
}
