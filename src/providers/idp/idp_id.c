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
#include "util/sss_chain_id.h"
#include "providers/idp/idp_id.h"




errno_t set_oidc_extra_args(TALLOC_CTX *mem_ctx, struct idp_id_ctx *idp_id_ctx,
                            const char *filter_value, int filter_type,
                            const char ***oidc_child_extra_args)
{
    const char **extra_args;
    uint64_t chain_id;
    size_t c = 0;
    int ret;

    if (idp_id_ctx == NULL || oidc_child_extra_args == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing required parameter.\n");
        return EINVAL;
    }

    if (filter_type != BE_FILTER_NAME) {
        DEBUG(SSSDBG_OP_FAILURE, "Unsupported filter type [%d].\n",
                                 filter_type);
        return EINVAL;
    }

    extra_args = talloc_zero_array(mem_ctx, const char *, 50);
    if (extra_args == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array() failed.\n");
        return ENOMEM;
    }

    extra_args[c] = talloc_strdup(extra_args, "--get-user");
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    c++;

    extra_args[c] = talloc_asprintf(extra_args,
                                    "--client-id=%s",
                                    idp_id_ctx->client_id);
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    c++;

    extra_args[c] = talloc_asprintf(extra_args,
                                    "--client-secret=%s",
                                    idp_id_ctx->client_secret);
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    c++;

    extra_args[c] = talloc_asprintf(extra_args,
                                    "--token-endpoint=%s",
                                    idp_id_ctx->token_endpoint);
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    c++;

    extra_args[c] = talloc_asprintf(extra_args,
                                    "--scope=%s",
                                    idp_id_ctx->scope);
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    c++;

    extra_args[c] = talloc_asprintf(extra_args,
                                    "--name=%s",
                                    filter_value);
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    c++;

    chain_id = sss_chain_id_get();
    extra_args[c] = talloc_asprintf(extra_args,
                                    "--chain-id=%lu",
                                    chain_id);
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }
    c++;

    extra_args[c] = NULL;

    *oidc_child_extra_args = extra_args;

    ret = EOK;

done:

    if (ret != EOK) {
        talloc_free(extra_args);
    }

    return ret;
}

struct idp_users_get_state {
    struct idp_req *idp_req;
    int dp_error;
    int idp_ret;
};

static void idp_users_get_done(struct tevent_req *subreq);

struct tevent_req *idp_users_get_send(TALLOC_CTX *memctx,
                                      struct tevent_context *ev,
                                      struct idp_id_ctx *idp_id_ctx,
                                      const char *filter_value,
                                      int filter_type,
                                      const char *extra_value,
                                      bool noexist_delete,
                                      bool set_non_posix)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct idp_users_get_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct idp_users_get_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create() failed.\n");
        return NULL;
    }

    state->dp_error = DP_ERR_FATAL;
    state->idp_ret = ENODATA;

    state->idp_req = talloc_zero(state, struct idp_req);
    if (state->idp_req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for IdP request.\n");
        ret = ENOMEM;
        goto immediately;
    }

    state->idp_req->idp_id_ctx = idp_id_ctx;

    ret = set_oidc_extra_args(state, idp_id_ctx, filter_value, filter_type,
                              &state->idp_req->oidc_child_extra_args);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "set_oidc_extra_args() failed.\n");
        goto immediately;
    }

    subreq = handle_oidc_child_send(state, ev, state->idp_req);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "handle_oidc_child_send() failed.\n");
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, idp_users_get_done, req);

    return req;

immediately:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    return tevent_req_post(req, ev);
}

static void idp_users_get_done(struct tevent_req *subreq)
{
    struct idp_users_get_state *state;
    struct tevent_req *req;
    errno_t ret;

    uint8_t *buf;
    ssize_t buflen;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct idp_users_get_state);

    ret = handle_oidc_child_recv(subreq, state, &buf, &buflen);
    talloc_zfree(subreq);
    if (ret != EOK) {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_ALL, "[%zd][%.*s]\n", buflen, (int) buflen, buf);
    ret = eval_user_buf(state->idp_req->idp_id_ctx, buf, buflen);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to evaluate user data returned by oidc_child.\n");
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}


int idp_users_get_recv(struct tevent_req *req, int *dp_error_out, int *idp_ret)
{
    struct idp_users_get_state *state;

    state = tevent_req_data(req, struct idp_users_get_state);

    if (dp_error_out != NULL) {
        *dp_error_out = state->dp_error;
    }

    if (idp_ret != NULL) {
        *idp_ret = state->idp_ret;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct tevent_req *idp_groups_get_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct idp_id_ctx *idp_id_ctx,
                                       const char *filter_value,
                                       int filter_type,
                                       bool noexist_delete,
                                       bool no_members,
                                       bool set_non_posix)
{
    return NULL;
}

int idp_groups_get_recv(struct tevent_req *req, int *dp_error_out, int *idp_ret)
{
    return ENOTSUP;
}

struct tevent_req *idp_groups_by_user_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct idp_id_ctx *idp_id_ctx,
                                           const char *filter_value,
                                           int filter_type,
                                           const char *extra_value,
                                           bool noexist_delete,
                                           bool set_non_posix)
{
    return NULL;
}

int idp_groups_by_user_recv(struct tevent_req *req, int *dp_error_out, int *idp_ret)
{
    return ENOTSUP;
}

struct idp_handle_acct_req_state {
    struct dp_id_data *ar;
    const char *err;
    int dp_error;
    int idp_ret;
};

static void idp_handle_acct_req_done(struct tevent_req *subreq);

static struct tevent_req *
idp_handle_acct_req_send(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         struct dp_id_data *ar,
                         struct idp_id_ctx *idp_id_ctx,
                         bool noexist_delete)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct idp_handle_acct_req_state *state;
    errno_t ret;


    req = tevent_req_create(mem_ctx, &state,
                            struct idp_handle_acct_req_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create() failed.\n");
        return NULL;
    }
    state->ar = ar;

    if (ar == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing input.\n");
        ret = EINVAL;
        goto done;
    }

    switch (ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER: /* user */
        subreq = idp_users_get_send(state, be_ctx->ev, idp_id_ctx,
                                    ar->filter_value,
                                    ar->filter_type,
                                    ar->extra_value,
                                    noexist_delete,
                                    false);
        break;

    case BE_REQ_GROUP: /* group */
        subreq = idp_groups_get_send(state, be_ctx->ev, idp_id_ctx,
                                     ar->filter_value,
                                     ar->filter_type,
                                     noexist_delete, false, false);
        break;

    case BE_REQ_INITGROUPS: /* init groups for user */
        if (ar->filter_type != BE_FILTER_NAME) {
            ret = EINVAL;
            state->err = "Invalid filter type";
            goto done;
        }

        subreq = idp_groups_by_user_send(state, be_ctx->ev, idp_id_ctx,
                                         ar->filter_value,
                                         ar->filter_type,
                                         ar->extra_value,
                                         noexist_delete, false);
        break;
    default: /*fail*/
        ret = EINVAL;
        state->err = "Invalid request type";
        DEBUG(SSSDBG_OP_FAILURE,
              "Unexpected request type: 0x%X [%s:%s] in %s\n",
              ar->entry_type, ar->filter_value,
              ar->extra_value?ar->extra_value:"-",
              ar->domain);
        goto done;
    }

    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, idp_handle_acct_req_done, req);
    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    tevent_req_post(req, be_ctx->ev);
    return req;
}

static void idp_handle_acct_req_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct idp_handle_acct_req_state *state;
    errno_t ret;
    const char *err = "Invalid request type";

    state = tevent_req_data(req, struct idp_handle_acct_req_state);

    switch (state->ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER: /* user */
        err = "User lookup failed";
        ret = idp_users_get_recv(subreq, &state->dp_error, &state->idp_ret);
        break;
    case BE_REQ_GROUP: /* group */
        err = "Group lookup failed";
        ret = idp_groups_get_recv(subreq, &state->dp_error, &state->idp_ret);
        break;
    case BE_REQ_INITGROUPS: /* init groups for user */
        err = "Init group lookup failed";
        ret = idp_groups_by_user_recv(subreq, &state->dp_error, &state->idp_ret);
        break;
    default: /* fail */
        ret = EINVAL;
        break;
    }
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->err = err;
        tevent_req_error(req, ret);
        return;
    }

    state->err = "Success";
    tevent_req_done(req);
}

static errno_t
idp_handle_acct_req_recv(struct tevent_req *req,
                          int *_dp_error, const char **_err,
                          int *idp_ret)
{
    struct idp_handle_acct_req_state *state;

    state = tevent_req_data(req, struct idp_handle_acct_req_state);

    if (_dp_error) {
        *_dp_error = state->dp_error;
    }

    if (_err) {
        *_err = state->err;
    }

    if (idp_ret) {
        *idp_ret = state->idp_ret;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct idp_account_info_handler_state {
    struct dp_reply_std reply;
};

static void idp_account_info_handler_done(struct tevent_req *subreq);

struct tevent_req *
idp_account_info_handler_send(TALLOC_CTX *mem_ctx,
                              struct idp_id_ctx *idp_id_ctx,
                              struct dp_id_data *data,
                              struct dp_req_params *params)
{
    struct idp_account_info_handler_state *state;
    struct tevent_req *subreq = NULL;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct idp_account_info_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    subreq = idp_handle_acct_req_send(state, params->be_ctx, data, idp_id_ctx,
                                      true);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "idp_handle_acct_req_send() failed.\n");
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

    //uint8_t *buf;
    //ssize_t buflen;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct idp_account_info_handler_state);

    ret = idp_handle_acct_req_recv(subreq, &dp_error, &error_msg, NULL);
    //ret = handle_oidc_child_recv(subreq, state, &buf, &buflen);
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
