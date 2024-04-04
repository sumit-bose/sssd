/*
    SSSD

    IdP Backend Module -- Authentication

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

#include <security/pam_modules.h>

#include "util/util.h"
#include "src/providers/idp/idp_auth.h"

struct idp_pam_auth_handler_state {
    struct tevent_context *ev;
    struct idp_auth_ctx *auth_ctx;
    struct be_ctx *be_ctx;
    struct pam_data *pd;
    struct sss_domain_info *dom;
};

struct tevent_req *
idp_pam_auth_handler_send(TALLOC_CTX *mem_ctx,
                          struct idp_auth_ctx *auth_ctx,
                          struct pam_data *pd,
                          struct dp_req_params *params)
{
    struct idp_pam_auth_handler_state *state;
    //struct tevent_req *subreq;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state,
                            struct idp_pam_auth_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->pd = pd;
    state->ev = params->ev;
    state->auth_ctx = auth_ctx;
    state->be_ctx = params->be_ctx;
    state->dom = find_domain_by_name(state->be_ctx->domain,
                                     state->pd->domain,
                                     true);
    if (state->dom == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown domain %s\n", state->pd->domain);
        pd->pam_status = PAM_SYSTEM_ERR;
        goto immediately;
    }

    pd->pam_status = PAM_SYSTEM_ERR;


    //return req;

immediately:
    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}
errno_t
idp_pam_auth_handler_recv(TALLOC_CTX *mem_ctx,
                          struct tevent_req *req,
                          struct pam_data **_data)
{
    struct idp_pam_auth_handler_state *state = NULL;

    state = tevent_req_data(req, struct idp_pam_auth_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_data = talloc_steal(mem_ctx, state->pd);

    return EOK;
}
