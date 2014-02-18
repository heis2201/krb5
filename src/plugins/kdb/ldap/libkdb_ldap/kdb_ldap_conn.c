/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/kdb/ldap/libkdb_ldap/kdb_ldap_conn.c */
/*
 * Copyright (c) 2004-2005, Novell, Inc.
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

#include "autoconf.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sasl/sasl.h>

#include "ldap_main.h"
#include "ldap_service_stash.h"
#include <kdb5.h>

static krb5_error_code
krb5_validate_ldap_context(krb5_context context,
                           krb5_ldap_context *ldap_context)
{
    krb5_error_code             st=0;
    unsigned char               *password=NULL;

    if ((ldap_context->auth_method==KRB5_LDAP_AUTH_NONE) ||
        (ldap_context->auth_method==KRB5_LDAP_AUTH_SASL))
        goto err_out;
    if (ldap_context->bind_dn == NULL) {
        st = EINVAL;
        krb5_set_error_message(context, st, _("LDAP bind dn value missing "));
        goto err_out;
    }

    if (ldap_context->bind_pwd == NULL && ldap_context->service_password_file == NULL) {
        st = EINVAL;
        krb5_set_error_message(context, st,
                               _("LDAP bind password value missing "));
        goto err_out;
    }

    if (ldap_context->bind_pwd == NULL) {
        if ((st=krb5_ldap_readpassword(context, ldap_context, &password)) != 0) {
            prepend_err_str(context, _("Error reading password from stash: "),
                            st, st);
            goto err_out;
        }

        ldap_context->bind_pwd = (char *)password;
        if (ldap_context->bind_pwd == NULL) {
            st = EINVAL;
            krb5_set_error_message(context, st,
                                   _("Error reading password from stash"));
            goto err_out;
        }
    }

    /* NULL password not allowed */
    if (ldap_context->bind_pwd != NULL && strlen(ldap_context->bind_pwd) == 0) {
        st = EINVAL;
        krb5_set_error_message(context, st,
                               _("Service password length is zero"));
        goto err_out;
    }

err_out:
    return st;
}

static int
krb5_ldap_sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *sin)
{
    sasl_interact_t *in = NULL;
    krb5_ldap_context *ldap_context = defaults;
    int ret = LDAP_OTHER;

    if (ldap_context == NULL) {
       in->result = NULL;
       in->len = 0;
       ret = LDAP_OTHER;
    }

    if (ld == NULL || sin == NULL)
        return LDAP_PARAM_ERROR;

    for (in = sin; in != NULL && in->id != SASL_CB_LIST_END; in++) {
        switch (in->id) {
        case SASL_CB_USER:
            if (ldap_context->sasl_user) {
                in->result = ldap_context->sasl_user;
                in->len = strlen(ldap_context->sasl_user);
            } else {
                in->result = NULL;
                in->len = 0;
            }
            ret = LDAP_SUCCESS;
            break;
        case SASL_CB_GETREALM:
            if (ldap_context->sasl_realm) {
                in->result = ldap_context->sasl_realm;
                in->len = strlen(ldap_context->sasl_realm);
            } else {
                in->result = NULL;
                in->len = 0;
            }
            ret = LDAP_SUCCESS;
            break;
        case SASL_CB_AUTHNAME:
            if (ldap_context->sasl_auth_user) {
                in->result = ldap_context->sasl_auth_user;
                in->len = strlen(ldap_context->sasl_auth_user);
            } else {
                in->result = NULL;
                in->len = 0;
            }
            ret = LDAP_SUCCESS;
            break;
        case SASL_CB_PASS:
            if (ldap_context->sasl_secret) {
                in->result = ldap_context->sasl_secret;
                in->len = strlen(ldap_context->sasl_secret);
            } else {
                in->result = NULL;
                in->len = 0;
            }
            ret = LDAP_SUCCESS;
            break;
        default:
            in->result = NULL;
            in->len = 0;
            ret = LDAP_OTHER;
        }
    }

    return ret;
}


/*
 * Internal Functions called by init functions.
 */

static krb5_error_code
krb5_ldap_bind(krb5_ldap_context *ldap_context,
               krb5_ldap_server_handle *ldap_server_handle)
{
    krb5_error_code             st=0;

    switch(ldap_context->auth_method) {
    case KRB5_LDAP_AUTH_NONE:
        st = ldap_simple_bind_s(ldap_server_handle->ldap_handle, NULL, NULL);
        break;
    case KRB5_LDAP_AUTH_SIMPLE:
        st = ldap_simple_bind_s(ldap_server_handle->ldap_handle,
                                ldap_context->bind_dn,
                                ldap_context->bind_pwd);
        break;
    case KRB5_LDAP_AUTH_SASL:
        st = ldap_sasl_interactive_bind_s(ldap_server_handle->ldap_handle,
                                          NULL,
                                          ldap_context->sasl_mech,
                                          NULL,
                                          NULL,
                                          LDAP_SASL_QUIET,
                                          &krb5_ldap_sasl_interact,
                                          (void *)ldap_context);
        break;
    }
    return st;
}

static krb5_error_code
krb5_ldap_initialize(krb5_ldap_context *ldap_context,
                     krb5_ldap_server_info *server_info)
{
    krb5_error_code             st=0;
    krb5_ldap_server_handle     *ldap_server_handle=NULL;


    ldap_server_handle = calloc(1, sizeof(krb5_ldap_server_handle));
    if (ldap_server_handle == NULL) {
        st = ENOMEM;
        goto err_out;
    }

    /* ldap init */
    if ((st = ldap_initialize(&ldap_server_handle->ldap_handle, server_info->server_name)) != 0) {
        krb5_set_error_message(ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR,
                               _("Cannot create LDAP handle for '%s': %s"),
                               server_info->server_name, ldap_err2string(st));
        st = KRB5_KDB_ACCESS_ERROR;
        goto err_out;
    }

    if (ldap_context->starttls
            && !(strlen(server_info->server_name)>8 && strncmp(server_info->server_name, "ldaps://", 8)==0)
            && (st = ldap_start_tls_s(ldap_server_handle->ldap_handle, NULL, NULL) != LDAP_SUCCESS)) {
        if (ldap_context->kcontext)
            krb5_set_error_message (ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR, "LDAP StartTLS failed. %s",
                                    ldap_err2string(st));
        st = KRB5_KDB_ACCESS_ERROR;
        goto err_out;
    }

    if ((st=krb5_ldap_bind(ldap_context, ldap_server_handle)) == 0) {
        ldap_server_handle->server_info_update_pending = FALSE;
        server_info->server_status = ON;
        krb5_update_ldap_handle(ldap_server_handle, server_info);
    } else {
        krb5_set_error_message(ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR,
                               _("Cannot bind to LDAP server '%s' as '%s'"
                                 ": %s"), server_info->server_name,
                               ldap_context->bind_dn, ldap_err2string(st));
        st = KRB5_KDB_ACCESS_ERROR;
        server_info->server_status = OFF;
        time(&server_info->downtime);
        /* ldap_unbind_s(ldap_server_handle->ldap_handle); */
        free(ldap_server_handle);
    }

err_out:
    return st;
}

/*
 * initialization for data base routines.
 */

krb5_error_code
krb5_ldap_db_init(krb5_context context, krb5_ldap_context *ldap_context)
{
    krb5_error_code             st=0;
    krb5_boolean                sasl_mech_supported=TRUE;
    int                         cnt=0, version=LDAP_VERSION3;
    struct timeval              local_timelimit = {10,0};

    if ((st=krb5_validate_ldap_context(context, ldap_context)) != 0)
        return st;

#ifdef LDAP_OPT_DEBUG_LEVEL
    ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &ldap_context->ldap_debug);
#endif
    ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &version);
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    ldap_set_option(NULL, LDAP_OPT_NETWORK_TIMEOUT, &local_timelimit);
#elif defined LDAP_X_OPT_CONNECT_TIMEOUT
    ldap_set_option(NULL, LDAP_X_OPT_CONNECT_TIMEOUT, &local_timelimit);
#endif

    HNDL_LOCK(ldap_context);

    if (ldap_context->tls_cacert_file) {
        st = ldap_set_option (NULL,
                        LDAP_OPT_X_TLS_CACERTFILE,
                        ldap_context->tls_cacert_file);
        if (st != LDAP_OPT_SUCCESS) {
            krb5_set_error_message (ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR,
                                    "Could not set TLS_CACERTFILE: %s",
                                    ldap_err2string(st));
            return KRB5_KDB_ACCESS_ERROR;
        }
    }
    if (ldap_context->tls_cacert_dir) {
        st = ldap_set_option (NULL,
                        LDAP_OPT_X_TLS_CACERTDIR,
                        ldap_context->tls_cacert_file);
        if (st != LDAP_OPT_SUCCESS) {
            krb5_set_error_message (ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR,
                                    "Could not set TLS_CACERTDIR: %s",
                                    ldap_err2string(st));
            return KRB5_KDB_ACCESS_ERROR;
        }
    }
    if (ldap_context->tls_cert_file) {
        st = ldap_set_option (NULL,
                        LDAP_OPT_X_TLS_CERTFILE,
                        ldap_context->tls_cert_file);
        if (st != LDAP_OPT_SUCCESS) {
            krb5_set_error_message (ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR,
                                    "Could not set TLS_CERTFILE: %s",
                                    ldap_err2string(st));
            return KRB5_KDB_ACCESS_ERROR;
        }
    }
    if (ldap_context->tls_cert_key_file) {
        st = ldap_set_option (NULL,
                        LDAP_OPT_X_TLS_KEYFILE,
                        ldap_context->tls_cert_key_file);
        if (st != LDAP_OPT_SUCCESS) {
            krb5_set_error_message (ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR,
                                    "Could not set TLS_KEYFILE: %s",
                                    ldap_err2string(st));
            return KRB5_KDB_ACCESS_ERROR;
        }
    }
    if (ldap_context->tls_reqcert!=-1) {
        st = ldap_set_option (NULL,
                        LDAP_OPT_X_TLS_REQUIRE_CERT,
                        &ldap_context->tls_reqcert);
        if (st != LDAP_OPT_SUCCESS) {
            krb5_set_error_message (ldap_context->kcontext, KRB5_KDB_ACCESS_ERROR,
                                    "Could not set TLS_REQUIRE_CERT: %s",
                                    ldap_err2string(st));
            return KRB5_KDB_ACCESS_ERROR;
        }
    }

    ldap_set_option (NULL,
                    LDAP_OPT_X_TLS_CRLFILE,
                    ldap_context->tls_crl_file);
    ldap_set_option (NULL,
                    LDAP_OPT_X_TLS_CRLCHECK,
                    &ldap_context->tls_crlcheck);

    while (ldap_context->server_info_list[cnt] != NULL) {
        krb5_ldap_server_info *server_info=NULL;

        server_info = ldap_context->server_info_list[cnt];

        if (server_info->server_status == NOTSET) {
            unsigned int conns=0;

            /*
             * Check if the server has to perform SASL authentication
             */
            if (ldap_context->auth_method == KRB5_LDAP_AUTH_SASL) {
                /* Find out if the server supports SASL mechanism */
                if (has_sasl_mech(context, server_info->server_name, 
                                  ldap_context->sasl_mech) == 1) {
                    cnt++;
                    sasl_mech_supported = FALSE;
                    continue; /* Check the next LDAP server */
                }
                sasl_mech_supported = TRUE;
            }

            krb5_clear_error_message(context);

#ifdef LDAP_MOD_INCREMENT
            server_info->modify_increment =
                (has_modify_increment(context, server_info->server_name) == 0);
#else
            server_info->modify_increment = 0;
#endif /* LDAP_MOD_INCREMENT */

            for (conns=0; conns < ldap_context->max_server_conns; ++conns) {
                if ((st=krb5_ldap_initialize(ldap_context, server_info)) != 0)
                    break;
            } /* for (conn= ... */

            if (server_info->server_status == ON)
                break;  /* server init successful, so break */
        }
        ++cnt;
    }
    HNDL_UNLOCK(ldap_context);

    if (sasl_mech_supported == FALSE) {
        st = KRB5_KDB_ACCESS_ERROR;
        krb5_set_error_message(context, st,
                               _("LDAP servers do not support %s SASL "
                                 "mechanism"), ldap_context->sasl_mech);
    }
    return st;
}


/*
 * get a single handle. Do not lock the mutex
 */

krb5_error_code
krb5_ldap_db_single_init(krb5_ldap_context *ldap_context)
{
    krb5_error_code             st=0;
    int                         cnt=0;
    krb5_ldap_server_info       *server_info=NULL;

    while (ldap_context->server_info_list[cnt] != NULL) {
        server_info = ldap_context->server_info_list[cnt];
        if ((server_info->server_status == NOTSET || server_info->server_status == ON)) {
            if (server_info->num_conns < ldap_context->max_server_conns-1) {
                st = krb5_ldap_initialize(ldap_context, server_info);
                if (st == LDAP_SUCCESS)
                    goto cleanup;
            }
        }
        ++cnt;
    }

    /* If we are here, try to connect to all the servers */

    cnt = 0;
    while (ldap_context->server_info_list[cnt] != NULL) {
        server_info = ldap_context->server_info_list[cnt];
        st = krb5_ldap_initialize(ldap_context, server_info);
        if (st == LDAP_SUCCESS)
            goto cleanup;
        ++cnt;
    }
cleanup:
    return (st);
}

krb5_error_code
krb5_ldap_rebind(krb5_ldap_context *ldap_context,
                 krb5_ldap_server_handle **ldap_server_handle)
{
    krb5_ldap_server_handle     *handle = *ldap_server_handle;

    ldap_unbind_ext_s(handle->ldap_handle, NULL, NULL);
    if ((ldap_initialize(&handle->ldap_handle, handle->server_info->server_name) != LDAP_SUCCESS)
        || (krb5_ldap_bind(ldap_context, handle) != LDAP_SUCCESS))
        return krb5_ldap_request_next_handle_from_pool(ldap_context, ldap_server_handle);
    return LDAP_SUCCESS;
}

/*
 *     DAL API functions
 */
krb5_error_code
krb5_ldap_lib_init()
{
    return 0;
}

krb5_error_code
krb5_ldap_lib_cleanup()
{
    /* right now, no cleanup required */
    return 0;
}

krb5_error_code
krb5_ldap_free_ldap_context(krb5_ldap_context *ldap_context)
{
    if (ldap_context == NULL)
        return 0;

    free(ldap_context->container_dn);
    ldap_context->container_dn = NULL;

    krb5_ldap_free_realm_params(ldap_context->lrparams);
    ldap_context->lrparams = NULL;

    krb5_ldap_free_server_params(ldap_context);

    return 0;
}

krb5_error_code
krb5_ldap_close(krb5_context context)
{
    kdb5_dal_handle  *dal_handle=NULL;
    krb5_ldap_context *ldap_context=NULL;

    if (context == NULL ||
        context->dal_handle == NULL ||
        context->dal_handle->db_context == NULL)
        return 0;

    dal_handle = context->dal_handle;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;
    dal_handle->db_context = NULL;

    krb5_ldap_free_ldap_context(ldap_context);

    return 0;
}
