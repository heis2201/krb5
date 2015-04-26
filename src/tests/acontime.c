/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* tests/acontime.c - Time test harness for X25519 */
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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <krb5.h>

static krb5_context ctx;

static void
check(krb5_error_code code)
{
    const char *errmsg;

    if (code) {
        errmsg = krb5_get_error_message(ctx, code);
        fprintf(stderr, "%s\n", errmsg);
        krb5_free_error_message(ctx, errmsg);
        exit(1);
    }
}

static void
test_context(krb5_creds *cred, krb5_keytab keytab, krb5_boolean do_x25519)
{
    krb5_flags ap_opts;
    krb5_auth_context icon, acon;
    krb5_data msg;
    krb5_ap_rep_enc_part *repl;

    ap_opts = AP_OPTS_MUTUAL_REQUIRED | AP_OPTS_ETYPE_NEGOTIATION;
    if (do_x25519)
        ap_opts |= AP_OPTS_X25519;

    /* Initialize auth contexts and disable replay detection. */
    check(krb5_auth_con_init(ctx, &icon));
    check(krb5_auth_con_init(ctx, &acon));
    check(krb5_auth_con_setflags(ctx, icon, 0));
    check(krb5_auth_con_setflags(ctx, acon, 0));

    check(krb5_mk_req_extended(ctx, &icon, ap_opts, NULL, cred, &msg));
    check(krb5_rd_req(ctx, &acon, &msg, NULL, keytab, NULL, NULL));
    krb5_free_data_contents(ctx, &msg);
    check(krb5_mk_rep(ctx, acon, &msg));
    check(krb5_rd_rep(ctx, icon, &msg, &repl));
    krb5_free_ap_rep_enc_part(ctx, repl);
    krb5_free_data_contents(ctx, &msg);

    krb5_auth_con_free(ctx, icon);
    krb5_auth_con_free(ctx, acon);
}

int
main(int argc, char **argv)
{
    krb5_principal client, server;
    krb5_ccache ccache;
    krb5_keytab keytab;
    krb5_creds in_cred, *cred;
    krb5_boolean do_x25519;
    int iterations, i;

    check(krb5_init_context(&ctx));

    /* Parse arguments. */
    assert(argc == 4);
    check(krb5_parse_name(ctx, argv[1], &server));
    iterations = atoi(argv[2]);
    do_x25519 = (*argv[3] == 'y');

    /* Get a credential for the target service. */
    check(krb5_cc_default(ctx, &ccache));
    check(krb5_cc_get_principal(ctx, ccache, &client));
    memset(&in_cred, 0, sizeof(in_cred));
    in_cred.client = client;
    in_cred.server = server;
    check(krb5_get_credentials(ctx, 0, ccache, &in_cred, &cred));

    check(krb5_kt_default(ctx, &keytab));

    for (i = 0; i < iterations; i++)
        test_context(cred, keytab, do_x25519);

    krb5_free_creds(ctx, cred);
    krb5_free_principal(ctx, client);
    krb5_free_principal(ctx, server);
    krb5_cc_close(ctx, ccache);
    krb5_kt_close(ctx, keytab);
    krb5_free_context(ctx);
    return 0;
}
