/*
    SSSD

    IdP Identity Backend Module - evalute replies

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
#include <jansson.h>

#include "util/util.h"
#include "providers/idp/idp_id.h"

errno_t store_json_user(struct idp_id_ctx *idp_id_ctx, json_t *user)
{
    // sdap_save_user
    errno_t ret;
    json_t *user_name = NULL;
    json_t *uuid = NULL;
    const char *gecos = NULL; /* given name + surname */
    const char *homedir = NULL;
    const char *shell = NULL;
    int cache_timeout;
    struct sss_domain_info *dom;
    uid_t uid;
    gid_t gid;
    char *fqdn = NULL;
    enum idmap_error_code err;

    dom = idp_id_ctx->be_ctx->domain;


    user_name = json_object_get(user, "displayName");
    if (!json_is_string(user_name)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "JSON user object does not contain 'displayName' string.\n");
        ret = EINVAL;
        goto done;
    }

    fqdn = sss_create_internal_fqname(idp_id_ctx, json_string_value(user_name),
                                      dom->name);
    if (fqdn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate fully-qualified name.\n");
        ret = ENOMEM;
        goto done;
    }

    uuid = json_object_get(user, "id");
    if (!json_is_string(uuid)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "JSON user object does not contain 'id' string.\n");
        ret = EINVAL;
        goto done;
    }

    err = sss_idmap_gen_to_unix(idp_id_ctx->idmap_ctx,
                                idp_id_ctx->token_endpoint,
                                json_string_value(uuid), &uid);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate UID for [%s][%s].\n",
                                 fqdn, json_string_value(uuid));
        ret = EIO;
        goto done;
    }
    gid = uid;

    cache_timeout = dom->user_timeout;
    ret = sysdb_store_user(dom, fqdn, NULL,
                           uid, gid, gecos, homedir, shell, NULL, NULL, NULL,
                           cache_timeout, 0);

done:
    talloc_free(fqdn);

    return ret;
}

errno_t eval_user_buf(struct idp_id_ctx *idp_id_ctx,
                      uint8_t *buf, ssize_t buflen)
{
    errno_t ret;
    json_t *data = NULL;
    json_error_t json_error;
    char *tmp = NULL;
    size_t index;
    json_t *user;

    data = json_loadb((char *) buf, buflen, 0, &json_error);
    if (data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse user data on line [%d]: [%s].\n",
              json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    if (!json_is_array(data)) {
        DEBUG(SSSDBG_OP_FAILURE, "Array of users expected.\n");
        ret = EINVAL;
        goto done;
    }

    tmp = json_dumps(data, 0);
    if (tmp != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "JSON: %s\n", tmp);
        free(tmp);
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "json_dumps() failed.\n");
    }

    json_array_foreach(data, index, user) {
        ret = store_json_user(idp_id_ctx, user);
        if (ret != EOK) {
            tmp = json_dumps(user, 0);
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store JSON user [%s].\n", tmp);
            free(tmp);
        }
    }

    ret = EOK;
done:
    json_decref(data);

    return ret;
}

