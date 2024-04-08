/*
    SSSD

    IdP Identity Backend Module

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include <errno.h>

#include "util/util.h"
#include "providers/idp/idp_id.h"

struct idp_account_info_handler_state {
    struct dp_reply_std reply;
};

static void idp_account_info_handler_done(struct tevent_req *subreq);

struct tevent_req *
idp_account_info_handler_send(TALLOC_CTX *mem_ctx,
                              struct idp_id_ctx *id_ctx,
                              struct dp_id_data *data,
                              struct dp_req_params *params)
{
    struct idp_account_info_handler_state *state;
    struct tevent_req *subreq = NULL;
    struct tevent_req *req;
    errno_t ret;

    struct idp_req *idp_req;

    req = tevent_req_create(mem_ctx, &state,
                            struct idp_account_info_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    idp_req = talloc_zero(state, struct idp_req);
    if (idp_req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for IdP request.\n");
        ret = ENOMEM;
        goto immediately;
    }

    idp_req->idp_ctx = id_ctx;

    subreq = handle_oidc_child_send(state, params->be_ctx->ev, idp_req);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "handle_oidc_child_send() failed.\n");
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, idp_account_info_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void idp_account_info_handler_done(struct tevent_req *subreq)
{
    struct idp_account_info_handler_state *state;
    struct tevent_req *req;
    const char *error_msg = NULL;
    int dp_error = DP_ERR_FATAL;
    errno_t ret;

    uint8_t *buf;
    ssize_t buflen;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct idp_account_info_handler_state);

    ret = handle_oidc_child_recv(subreq, state, &buf, &buflen);
    talloc_zfree(subreq);

    /* TODO For backward compatibility we always return EOK to DP now. */
    dp_reply_std_set(&state->reply, dp_error, ret, error_msg);
    tevent_req_done(req);
}

errno_t idp_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct dp_reply_std *data)
{
    struct idp_account_info_handler_state *state = NULL;

    state = tevent_req_data(req, struct idp_account_info_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
