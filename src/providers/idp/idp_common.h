/*
    SSSD

    IdP Backend, common header file

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat


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

#ifndef __IDP_COMMON_H__
#define __IDP_COMMON_H__

#include "config.h"
#include <stdbool.h>

#include "providers/backend.h"
#include "util/util.h"

enum krb5_opts {
    IDP_OPENID_CONFIGURATION = 0,
    IDP_REQ_TIMEOUT,
    IDP_CLIENT_ID,
    IDP_CLIENT_SECRET,
    IDP_TOKEN_ENDPOINT,
    IDP_SCOPE,

    IDP_OPTS
};

struct idp_id_ctx;

struct idp_req {
    struct idp_id_ctx *idp_id_ctx;
    const char **oidc_child_extra_args;
};


struct tevent_req *
idp_online_check_handler_send(TALLOC_CTX *mem_ctx,
                              struct idp_id_ctx *id_ctx,
                              void *data,
                              struct dp_req_params *params);

errno_t idp_online_check_handler_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct dp_reply_std *data);

/* oidc_child_handler.c */
struct tevent_req *handle_oidc_child_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct idp_req *idp_req);

int handle_oidc_child_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                           uint8_t **buf, ssize_t *len);
#endif /* __IDP_COMMON_H__ */
