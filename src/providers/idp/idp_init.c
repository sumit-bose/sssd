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
#include "lib/idmap/sss_idmap.h"
#include "util/util_sss_idmap.h"

struct idp_init_ctx {
    struct be_ctx *be_ctx;
    struct dp_option *opts;
    struct idp_id_ctx *id_ctx;
    struct idp_auth_ctx *auth_ctx;

    const char *client_id;
    const char *client_secret;
    const char *token_endpoint;
    const char *scope;
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

    init_ctx->be_ctx = be_ctx;

    /* Always initialize options since it is needed everywhere. */
    ret = idp_get_options(init_ctx, be_ctx->cdb, be_ctx->conf_path,
                          &init_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize IdP options "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    init_ctx->client_id = dp_opt_get_cstring(init_ctx->opts,
                                             IDP_CLIENT_ID);
    if (init_ctx->client_id == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_client_id'.\n");
        ret = EINVAL;
        goto done;
    }

    init_ctx->client_secret = dp_opt_get_cstring(init_ctx->opts,
                                                 IDP_CLIENT_SECRET);
    if (init_ctx->client_secret == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_client_secret'.\n");
        ret = EINVAL;
        goto done;
    }

    init_ctx->token_endpoint = dp_opt_get_cstring(init_ctx->opts,
                                                  IDP_TOKEN_ENDPOINT);
    if (init_ctx->token_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_token_endpoint'.\n");
        ret = EINVAL;
        goto done;
    }

    init_ctx->scope = dp_opt_get_cstring(init_ctx->opts, IDP_ID_SCOPE);
    if (init_ctx->scope == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_scope'.\n");
        ret = EINVAL;
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
    errno_t ret;
    enum idmap_error_code err;
    struct sss_idmap_range id_range;

    init_ctx = talloc_get_type(module_data, struct idp_init_ctx);

    id_ctx = talloc_zero(init_ctx, struct idp_id_ctx);
    if (id_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to allocate memory for id context.\n");
        return ENOMEM;
    }

    id_ctx->be_ctx = be_ctx;
    id_ctx->init_ctx = init_ctx;
    id_ctx->idp_options = init_ctx->opts;

    id_ctx->client_id = init_ctx->client_id;
    id_ctx->client_secret = init_ctx->client_secret;
    id_ctx->token_endpoint = init_ctx->token_endpoint;
    id_ctx->scope = init_ctx->scope;

    err = sss_idmap_init(sss_idmap_talloc, init_ctx, sss_idmap_talloc_free,
                         &id_ctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed in initialize id-mapping: [%s].\n",
                                   idmap_error_string(err));
        ret = EINVAL;
        goto done;
    }

    err = sss_idmap_calculate_range(id_ctx->idmap_ctx, id_ctx->token_endpoint /* TODO: use better value */,
                                    NULL, &id_range);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to calculate id range for [%s]: [%s].\n",
              id_ctx->token_endpoint, idmap_error_string(err));
        ret = EINVAL;
        goto done;
    }

    err = sss_idmap_add_gen_domain_ex(id_ctx->idmap_ctx, be_ctx->domain->name,
                                      id_ctx->token_endpoint, &id_range,
                                      NULL, NULL, NULL, NULL, 0, false);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to add id-mapping domain [%s]: [%s].\n",
              be_ctx->domain->name, idmap_error_string(err));
        ret = EINVAL;
        goto done;
    }


    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  idp_account_info_handler_send, idp_account_info_handler_recv, id_ctx,
                  struct idp_id_ctx, struct dp_id_data, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_CHECK_ONLINE,
                  idp_online_check_handler_send, idp_online_check_handler_recv, id_ctx,
                  struct idp_id_ctx, void, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send, default_account_domain_recv, NULL,
                  void, struct dp_get_acct_domain_data, struct dp_reply_std);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(id_ctx);
    }

    return ret;
}

errno_t sssm_idp_auth_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           void *module_data,
                           struct dp_method *dp_methods)
{
    struct idp_init_ctx *init_ctx;
    struct idp_auth_ctx *auth_ctx;
    int ret;

    init_ctx = talloc_get_type(module_data, struct idp_init_ctx);

    auth_ctx = talloc_zero(init_ctx, struct idp_auth_ctx);
    if (auth_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to allocate memory for auth context.\n");
        return ENOMEM;
    }

    auth_ctx->be_ctx = be_ctx;
    auth_ctx->init_ctx = init_ctx;
    auth_ctx->idp_options = init_ctx->opts;

    auth_ctx->client_id = init_ctx->client_id;
    auth_ctx->client_secret = init_ctx->client_secret;
    auth_ctx->token_endpoint = init_ctx->token_endpoint;

    auth_ctx->open_request_table = sss_ptr_hash_create(auth_ctx, NULL, NULL);
    if (auth_ctx->open_request_table == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create hash table.\n");
        ret = ENOMEM;
        goto done;
    }

    auth_ctx->scope = dp_opt_get_cstring(init_ctx->opts, IDP_AUTH_SCOPE);
    if (auth_ctx->scope == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_auth_scope'.\n");
        ret = EINVAL;
        goto done;
    }

    auth_ctx->device_auth_endpoint = dp_opt_get_cstring(init_ctx->opts,
                                                      IDP_DEVICE_AUTH_ENDPOINT);
    if (auth_ctx->device_auth_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_device_code_endpoint'.\n");
        ret = EINVAL;
        goto done;
    }

    auth_ctx->userinfo_endpoint = dp_opt_get_cstring(init_ctx->opts,
                                                     IDP_USERINFO_ENDPOINT);
    if (auth_ctx->userinfo_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Missing required option 'idp_userinfo_endpoint'.\n");
        ret = EINVAL;
        goto done;
    }

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  idp_pam_auth_handler_send, idp_pam_auth_handler_recv, auth_ctx,
                  struct idp_auth_ctx, struct pam_data, struct pam_data *);

    ret =  EOK;
done:
    if (ret != EOK) {
        talloc_free(auth_ctx);
    }

    return ret;
}
