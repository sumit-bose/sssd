/*
    SSSD

    IdP Identity Backend Module

    Authors:
        Sumit Bose <jzeleny@redhat.com>

    Copyright (C) 2024 Red Hat

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


#ifndef _IDP_ID_H_
#define _IDP_ID_H_

#include "providers/idp/idp_common.h"
#include "lib/idmap/sss_idmap.h"

struct idp_id_ctx {
    struct be_ctx *be_ctx;
    struct idp_init_ctx *init_ctx;
    struct dp_option *idp_options;
    struct sss_idmap_ctx *idmap_ctx;

    const char *client_id;
    const char *client_secret;
    const char *token_endpoint;
    const char *scope;
};

struct tevent_req *
idp_account_info_handler_send(TALLOC_CTX *mem_ctx,
                              struct idp_id_ctx *id_ctx,
                              struct dp_id_data *data,
                              struct dp_req_params *params);

errno_t idp_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct dp_reply_std *data);


errno_t eval_user_buf(struct idp_id_ctx *idp_id_ctx,
                      const char *group_name,
                      uint8_t *buf, ssize_t buflen);

errno_t eval_group_buf(struct idp_id_ctx *idp_id_ctx,
                       const char *user_name,
                       uint8_t *buf, ssize_t buflen);
#endif
