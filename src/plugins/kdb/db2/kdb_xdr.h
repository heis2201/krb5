/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef _KDB2_XDR_H
#define _KDB2_XDR_H

#include "kdb.h"

krb5_error_code
krb5_dbe_decode_princ(krb5_context context, const void *enc, size_t len,
                      krb5_db_entry **entry_out);

krb5_error_code
krb5_dbe_encode_princ(krb5_context context, const krb5_db_entry *entry,
                      void **enc_out, size_t *len_out);

krb5_error_code
krb5_dbe_encode_policy(krb5_context context, osa_policy_ent_t entry,
                       void **enc_out, size_t *len_out);

krb5_error_code
krb5_dbe_decode_policy(krb5_context context, const void *enc, size_t len,
                       osa_policy_ent_t *entry_out);

#endif
