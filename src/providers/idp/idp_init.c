/*
    SSSD

    IdP Provider Initialization functions

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

#include "src/providers/data_provider.h"

#include "src/providers/idp/idp_common.h"
#include "src/providers/idp/idp_opts.h"
#include "src/providers/idp/idp_id.h"
#include "src/providers/idp/idp_auth.h"

struct idp_init_ctx {
    struct dp_option *opts;
    struct idp_id_ctx *id_ctx;
    struct idp_auth_ctx *auth_ctx;
};

static errno_t idp_get_options(TALLOC_CTX *mem_ctx,
                               struct confdb_ctx *cdb,
                               const char *conf_path,
                               struct dp_option **_opts)
{
    int ret;
    struct dp_option *opts;

    ret = dp_get_options(mem_ctx, cdb, conf_path, default_idp_opts,
                         IDP_OPTS, &opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dp_get_options failed.\n");
        goto done;
    }

    *_opts = opts;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(opts);
    }

    return ret;
}

errno_t sssm_idp_init(TALLOC_CTX *mem_ctx,
                      struct be_ctx *be_ctx,
                      struct data_provider *provider,
                      const char *module_name,
                      void **_module_data)
{
    struct idp_init_ctx *init_ctx;
    errno_t ret;

    init_ctx = talloc_zero(mem_ctx, struct idp_init_ctx);
    if (init_ctx == NULL) {
        return ENOMEM;
    }

    /* Always initialize options since it is needed everywhere. */
    ret = idp_get_options(init_ctx, be_ctx->cdb, be_ctx->conf_path,
                          &init_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize IdP options "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    *_module_data = init_ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(init_ctx);
    }

    return ret;
}
errno_t sssm_idp_id_init(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         void *module_data,
                         struct dp_method *dp_methods)
{
    struct idp_init_ctx *init_ctx;
    struct idp_id_ctx *id_ctx;

    init_ctx = talloc_get_type(module_data, struct idp_init_ctx);

    id_ctx = talloc_zero(init_ctx, struct idp_id_ctx);
    if (id_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to allocate memory for id context.\n");
        return ENOMEM;
    }

    id_ctx->init_ctx = init_ctx;
    id_ctx->idp_options = init_ctx->opts;

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  idp_account_info_handler_send, idp_account_info_handler_recv, id_ctx,
                  struct idp_id_ctx, struct dp_id_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_CHECK_ONLINE,
                  idp_online_check_handler_send, idp_online_check_handler_recv, id_ctx,
                  struct idp_id_ctx, void, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send, default_account_domain_recv, NULL,
                  void, struct dp_get_acct_domain_data, struct dp_reply_std);

    return EOK;
}

errno_t sssm_idp_auth_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           void *module_data,
                           struct dp_method *dp_methods)
{
    struct idp_init_ctx *init_ctx;
    struct idp_auth_ctx *auth_ctx;

    init_ctx = talloc_get_type(module_data, struct idp_init_ctx);
    auth_ctx = init_ctx->auth_ctx;

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  idp_pam_auth_handler_send, idp_pam_auth_handler_recv, auth_ctx,
                  struct idp_auth_ctx, struct pam_data, struct pam_data *);

    return EOK;
}
