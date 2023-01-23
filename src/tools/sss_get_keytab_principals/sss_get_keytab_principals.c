/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2023 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <errno.h>
#include <krb5/krb5.h>


int main(int argc, char *argv[])
{
    krb5_context krb_ctx = NULL;
    krb5_keytab keytab = NULL;
    krb5_error_code kerr;
    krb5_kt_cursor cursor = NULL;
    krb5_keytab_entry entry;
    char *princ_str;
    size_t c = 0;

    if (argc > 2) {
        kerr = EINVAL;
        goto done;
    }

    kerr = krb5_init_context(&krb_ctx);
    if (kerr != 0) {
        goto done;
    }

    if (argc == 2) {
        kerr = krb5_kt_resolve(krb_ctx, argv[1], &keytab);
    } else {
        kerr = krb5_kt_default(krb_ctx, &keytab);
    }
    if (kerr != 0) {
        goto done;
    }

    kerr = krb5_kt_start_seq_get(krb_ctx, keytab, &cursor);
    if (kerr != 0) {
        goto done;
    }

    while ((kerr = krb5_kt_next_entry(krb_ctx, keytab, &entry, &cursor)) == 0) {
        kerr = krb5_unparse_name(krb_ctx, entry.principal, &princ_str);
        krb5_kt_free_entry(krb_ctx, &entry);
        if (kerr != 0) {
            goto done;
        }
        fprintf(stdout, "%s%s", (c++ == 0) ? "" : ",", princ_str);
        krb5_free_unparsed_name(krb_ctx, princ_str);
    };
    fflush(stdout);
    if (kerr == KRB5_KT_END) {
        kerr = 0;
    }

done:

    if (cursor != NULL) {
        krb5_kt_end_seq_get(krb_ctx, keytab, &cursor);
    }

    if (keytab != NULL) {
        krb5_kt_close(krb_ctx, keytab);
    }

    if (krb_ctx != NULL) {
        krb5_free_context(krb_ctx);
    }

    return kerr;
}

