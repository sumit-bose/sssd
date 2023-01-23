/*
    Generated by sbus code generator

    Copyright (C) 2017 Red Hat

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

#include <errno.h>
#include <stdint.h>
#include <talloc.h>
#include <stdbool.h>
#include <dbus/dbus.h>

#include "sbus/interface/sbus_iterator_readers.h"
#include "sbus/interface/sbus_iterator_writers.h"
#include "sss_iface/sbus_sss_arguments.h"

errno_t _sbus_sss_invoker_read_as
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_as *args)
{
    errno_t ret;

    ret = sbus_iterator_read_as(mem_ctx, iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_as
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_as *args)
{
    errno_t ret;

    ret = sbus_iterator_write_as(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_b
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_b *args)
{
    errno_t ret;

    ret = sbus_iterator_read_b(iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_b
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_b *args)
{
    errno_t ret;

    ret = sbus_iterator_write_b(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_iss
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_iss *args)
{
    errno_t ret;

    ret = sbus_iterator_read_i(iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_iss
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_iss *args)
{
    errno_t ret;

    ret = sbus_iterator_write_i(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_o
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_o *args)
{
    errno_t ret;

    ret = sbus_iterator_read_o(mem_ctx, iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_o
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_o *args)
{
    errno_t ret;

    ret = sbus_iterator_write_o(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_pam_data
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_pam_data *args)
{
    errno_t ret;

    ret = sbus_iterator_read_pam_data(mem_ctx, iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_pam_data
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_pam_data *args)
{
    errno_t ret;

    ret = sbus_iterator_write_pam_data(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_pam_response
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_pam_response *args)
{
    errno_t ret;

    ret = sbus_iterator_read_pam_response(mem_ctx, iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_pam_response
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_pam_response *args)
{
    errno_t ret;

    ret = sbus_iterator_write_pam_response(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_q
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_q *args)
{
    errno_t ret;

    ret = sbus_iterator_read_q(iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_q
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_q *args)
{
    errno_t ret;

    ret = sbus_iterator_write_q(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_qus
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_qus *args)
{
    errno_t ret;

    ret = sbus_iterator_read_q(iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_u(iter, &args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_qus
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_qus *args)
{
    errno_t ret;

    ret = sbus_iterator_write_q(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_u(iter, args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_s
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_s *args)
{
    errno_t ret;

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_s
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_s *args)
{
    errno_t ret;

    ret = sbus_iterator_write_s(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_sqq
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_sqq *args)
{
    errno_t ret;

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_q(iter, &args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_q(iter, &args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_sqq
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_sqq *args)
{
    errno_t ret;

    ret = sbus_iterator_write_s(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_q(iter, args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_q(iter, args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_ss
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_ss *args)
{
    errno_t ret;

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg1);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_ss
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_ss *args)
{
    errno_t ret;

    ret = sbus_iterator_write_s(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg1);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_ssau
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_ssau *args)
{
    errno_t ret;

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_au(mem_ctx, iter, &args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_ssau
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_ssau *args)
{
    errno_t ret;

    ret = sbus_iterator_write_s(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_au(iter, args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_u
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_u *args)
{
    errno_t ret;

    ret = sbus_iterator_read_u(iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_u
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_u *args)
{
    errno_t ret;

    ret = sbus_iterator_write_u(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_usq
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_usq *args)
{
    errno_t ret;

    ret = sbus_iterator_read_u(iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_q(iter, &args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_usq
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_usq *args)
{
    errno_t ret;

    ret = sbus_iterator_write_u(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_q(iter, args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_ussu
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_ussu *args)
{
    errno_t ret;

    ret = sbus_iterator_read_u(iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg2);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_u(iter, &args->arg3);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_ussu
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_ussu *args)
{
    errno_t ret;

    ret = sbus_iterator_write_u(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg2);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_u(iter, args->arg3);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_usu
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_usu *args)
{
    errno_t ret;

    ret = sbus_iterator_read_u(iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_u(iter, &args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_usu
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_usu *args)
{
    errno_t ret;

    ret = sbus_iterator_write_u(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_u(iter, args->arg2);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_uusssu
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_uusssu *args)
{
    errno_t ret;

    ret = sbus_iterator_read_u(iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_u(iter, &args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg2);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg3);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg4);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_u(iter, &args->arg5);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_uusssu
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_uusssu *args)
{
    errno_t ret;

    ret = sbus_iterator_write_u(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_u(iter, args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg2);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg3);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg4);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_u(iter, args->arg5);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_uusu
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_uusu *args)
{
    errno_t ret;

    ret = sbus_iterator_read_u(iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_u(iter, &args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg2);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_u(iter, &args->arg3);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_uusu
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_uusu *args)
{
    errno_t ret;

    ret = sbus_iterator_write_u(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_u(iter, args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg2);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_u(iter, args->arg3);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_read_uuusu
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_uuusu *args)
{
    errno_t ret;

    ret = sbus_iterator_read_u(iter, &args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_u(iter, &args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_u(iter, &args->arg2);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, iter, &args->arg3);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_u(iter, &args->arg4);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t _sbus_sss_invoker_write_uuusu
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_uuusu *args)
{
    errno_t ret;

    ret = sbus_iterator_write_u(iter, args->arg0);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_u(iter, args->arg1);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_u(iter, args->arg2);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_s(iter, args->arg3);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_write_u(iter, args->arg4);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}
