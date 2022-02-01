/*
    SSSD

    Helper child to for OIDC

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2021 Red Hat

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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <popt.h>

#include <jose/jws.h>
#include <jose/b64.h>
#include <curl/curl.h>
#include <jansson.h>

#include "util/util.h"
#include "util/atomic_io.h"

struct devicecode_ctx {
    bool libcurl_debug;
    char *ca_db;
    char *device_authorization_endpoint;
    char *token_endpoint;
    char *userinfo_endpoint;
    char *jwks_uri;
    char *scope;

    char *data;
    char *user_code;
    char *device_code;
    char *verification_uri;
    char *verification_uri_complete;
    char *message;
    int interval;
    int expires_in;
    char *device_code_reply;

    json_t *result;
    json_t *access_token;
    json_t *access_token_payload;
    char *access_token_str;
    json_t *id_token;
    json_t *id_token_payload;
    char *id_token_str;
    json_t *userinfo;
};

char *get_json_string(TALLOC_CTX *mem_ctx, json_t *root, const char *attr)
{
    json_t *tmp;
    char *str;

    tmp = json_object_get(root, attr);
    if (!json_is_string(tmp)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Result does not contain the '%s' string.\n", attr);
        return NULL;
    }

    str = talloc_strdup(mem_ctx, json_string_value(tmp));
    if (str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy '%s' string.\n", attr);
        return NULL;
    }

    return str;
}

char *get_json_scope(TALLOC_CTX *mem_ctx, json_t *root, const char *attr)
{
    json_t *tmp;
    json_t *s;
    size_t index;
    char *str = NULL;

    tmp = json_object_get(root, attr);
    if (!json_is_array(tmp)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Result does not contain the '%s' array.\n", attr);
        return NULL;
    }

    json_array_foreach(tmp, index, s) {
        if (!json_is_string(s)) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to read supported scopes.\n");
            talloc_free(str);
            return NULL;
        }

        if (str == NULL) {
            str = talloc_strdup(mem_ctx, json_string_value(s));
        } else {
            str = talloc_asprintf_append(str, "%%20%s", json_string_value(s));
        }
        if (str == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy '%s' string.\n", attr);
            return NULL;
        }

    }

    return str;
}

errno_t get_endpoints(json_t *inp, struct devicecode_ctx *dc_ctx)
{
    int ret;

    dc_ctx->device_authorization_endpoint = get_json_string(dc_ctx, inp,
                                               "device_authorization_endpoint");
    if (dc_ctx->device_authorization_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing device_authorization_endpoint in "
                                   "openid configuration.\n");
        ret = EINVAL;
        goto done;
    }
    dc_ctx->token_endpoint = get_json_string(dc_ctx, inp, "token_endpoint");
    if (dc_ctx->token_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing token_endpoint in openid "
                                   "configuration.\n");
        ret = EINVAL;
        goto done;
    }
    dc_ctx->userinfo_endpoint = get_json_string(dc_ctx, inp,
                                                "userinfo_endpoint");
    if (dc_ctx->userinfo_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing userinfo_endpoint in openid "
                                   "configuration.\n");
        ret = EINVAL;
        goto done;
    }

    dc_ctx->jwks_uri = get_json_string(dc_ctx, inp, "jwks_uri");
    if (dc_ctx->jwks_uri == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing jwks_uri in openid "
                                   "configuration.\n");
    }

    dc_ctx->scope = get_json_scope(dc_ctx, inp, "scopes_supported");
    if (dc_ctx->scope == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing scopes in openid "
                                   "configuration.\n");
    }

    ret = EOK;
done:
    return ret;
}

errno_t get_issuer(struct devicecode_ctx *dc_ctx, const char *issuer_name)
{
    int ret;
    json_t *inp = NULL;
    json_t *issuers = NULL;
    json_error_t json_error;
    json_t *i;
    json_t *name;
    size_t index;

    inp = json_load_file("issuers", 0, &json_error);
    if (inp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse issuers file on line [%d]: [%s].\n",
              json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    issuers = json_object_get(inp, "issuers");
    if (!json_is_array(issuers)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Issuers is not an array.\n");
        ret = EINVAL;
        goto done;
    }

    ret = ENOENT;
    json_array_foreach(issuers, index, i) {
        name = json_object_get(i, "name");
        if (!json_is_string(name)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Malformed issuer name.\n");
            continue;
        }
        if (strcmp(json_string_value(name), issuer_name) == 0) {
            ret = get_endpoints(i, dc_ctx);
            break;
        }
    }

done:
    json_decref(issuers);

    return ret;
}

errno_t set_endpoints(struct devicecode_ctx *dc_ctx,
                      const char *device_auth_endpoint,
                      const char *token_endpoint,
                      const char *userinfo_endpoint,
                      const char *jwks_uri,
                      const char *scope)
{
    int ret;

    dc_ctx->device_authorization_endpoint = talloc_strdup(dc_ctx,
                                                          device_auth_endpoint);
    if (dc_ctx->device_authorization_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing device_authorization_endpoint.\n");
        ret = EINVAL;
        goto done;
    }
    dc_ctx->token_endpoint = talloc_strdup(dc_ctx, token_endpoint);
    if (dc_ctx->token_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing token_endpoint.\n");
        ret = EINVAL;
        goto done;
    }
    dc_ctx->userinfo_endpoint = talloc_strdup(dc_ctx,userinfo_endpoint);
    if (dc_ctx->userinfo_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing userinfo_endpoint.\n");
        ret = EINVAL;
        goto done;
    }

    if (jwks_uri != NULL && *jwks_uri != '\0') {
        dc_ctx->jwks_uri = talloc_strdup(dc_ctx, jwks_uri);
        if (dc_ctx->jwks_uri == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing jwks_uri.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (scope != NULL && *scope != '\0') {
        dc_ctx->scope = talloc_strdup(dc_ctx, scope);
        if (dc_ctx->scope == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing scopes.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;
done:
    return ret;
}

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t realsize = size * nmemb;
    struct devicecode_ctx *data = (struct devicecode_ctx *) userdata;

    DEBUG(SSSDBG_TRACE_ALL, "%*s\n", (int) realsize, ptr);

    if (data->data == NULL) {
        data->data = talloc_strndup(data, ptr, realsize);
    } else {
        data->data = talloc_strndup_append(data->data, ptr, realsize);
    }
    if (data->data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy receved data.\n");
        return 0;
    }

    return realsize;
}

int libcurl_debug_callback(CURL *curl_ctx, curl_infotype type, char *data,
                           size_t size, void *userptr)
{
    static const char prefix[CURLINFO_END][3] = {
                                     "* ", "< ", "> ", "{ ", "} ", "{ ", "} " };
    char *str = NULL;

    switch (type) {
    case CURLINFO_TEXT:
    case CURLINFO_HEADER_IN:
    case CURLINFO_HEADER_OUT:
        str = talloc_asprintf(NULL, "%s%.*s", prefix[type], (int) size, data);
        if (str != NULL) {
            sss_debug_fn(__FILE__, __LINE__, __FUNCTION__, SSSDBG_TRACE_ALL,
                         "libcurl: %s", str);
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to create libcurl debug message.\n");
        }
        talloc_free(str);
        break;
    default:
        break;
    }

    return 0;
}

errno_t set_http_opts(CURL *curl_ctx, struct devicecode_ctx *dc_ctx,
                      const char *uri, const char *post_data, const char *token,
                      struct curl_slist *headers)
{
    CURLcode res;
    int ret;

    /* Only allow https */
    res = curl_easy_setopt(curl_ctx, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to enforce HTTPS.\n");
        ret = EIO;
        goto done;
    }

    if (dc_ctx->ca_db != NULL) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_CAINFO, dc_ctx->ca_db);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set CA DB path.\n");
            ret = EIO;
            goto done;
        }
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_URL, uri);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set URL.\n");
        ret = EIO;
        goto done;
    }

    if (dc_ctx->libcurl_debug) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_VERBOSE, 1L);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set verbose option.\n");
            ret = EIO;
            goto done;
        }
        res = curl_easy_setopt(curl_ctx, CURLOPT_DEBUGFUNCTION,
                               libcurl_debug_callback);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set debug callback.\n");
            ret = EIO;
            goto done;
        }
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_USERAGENT, "SSSD oidc_child/0.0");
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set useragent option.\n");
        ret = EIO;
        goto done;
    }

    if (headers != NULL) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_HTTPHEADER, headers);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add header to POST request.\n");
            ret = EIO;
            goto done;
        }
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_WRITEFUNCTION, write_callback);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add device code callback.\n");
        ret = EIO;
        goto done;
    }

    res = curl_easy_setopt(curl_ctx, CURLOPT_WRITEDATA, dc_ctx);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to add device code callback.\n");
        ret = EIO;
        goto done;
    }

    if (post_data != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "POST data: [%s].\n", post_data);
        res = curl_easy_setopt(curl_ctx, CURLOPT_POSTFIELDS, post_data);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add data to POST request.\n");
            ret = EIO;
            goto done;
        }
    }

    if (token != NULL) {
        res = curl_easy_setopt(curl_ctx, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set HTTP auth.\n");
            ret = EIO;
            goto done;
        }
        res = curl_easy_setopt(curl_ctx, CURLOPT_XOAUTH2_BEARER, token);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add token.\n");
            ret = EIO;
            goto done;
        }
    }

    ret = EOK;
done:

    return ret;
}

errno_t do_http_request(struct devicecode_ctx *dc_ctx, const char *uri,
                        const char *post_data, const char *token)
{
    CURL *curl_ctx = NULL;
    CURLcode res;
    int ret;
    long resp_code;
    struct curl_slist *headers = NULL;

    headers = curl_slist_append(headers, "Accept: application/json");

    curl_ctx = curl_easy_init();
    if (curl_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize curl.\n");
        ret = EIO;
        goto done;
    }

    ret = set_http_opts(curl_ctx, dc_ctx, uri, post_data, token, headers);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set http options.\n");
        goto done;
    }

    res = curl_easy_perform(curl_ctx);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to send request.\n");
        ret = EIO;
        goto done;
    }

    res = curl_easy_getinfo(curl_ctx, CURLINFO_RESPONSE_CODE, &resp_code);
    if (res != CURLE_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get response code.\n");
        ret = EIO;
        goto done;
    }

    if (resp_code != 200) {
        DEBUG(SSSDBG_OP_FAILURE, "Request failed, response code is [%ld].\n",
                                 resp_code);
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_ctx);
    return ret;
}

errno_t get_jwks(TALLOC_CTX *mem_ctx, struct devicecode_ctx *dc_data)
{
    int ret;

    talloc_free(dc_data->data);
    dc_data->data = NULL;

    ret = do_http_request(dc_data, dc_data->jwks_uri, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read jwks file [%s].\n",
                                 dc_data->jwks_uri);
    }

    return ret;

}

errno_t str_to_jws(TALLOC_CTX *mem_ctx, const char *inp, json_t **jws)
{
    char *pl;
    char *sig;
    json_t *o;
    int ret;
    char *str;

    str = talloc_strdup(mem_ctx, inp);
    if (str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy token string.\n");
        return ENOMEM;
    }

    pl = strchr(str, '.');
    if (pl == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "String does not look like serialized JWS, missing first '.'.\n");
        return EINVAL;
    }
    *pl = '\0';
    pl++;

    sig = strchr(pl, '.');
    if (sig == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "String does not look like serialized JWS, missing second '.'.\n");
        return EINVAL;
    }
    *sig = '\0';
    sig++;

    o = json_object();
    if (o == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create JSON object.\n");
        return EIO;
    }

    ret = json_object_set_new(o, "protected", json_string(str));
    if (ret == 0) {
        ret = json_object_set_new(o, "payload", json_string(pl));
    }
    if (ret == 0) {
        ret = json_object_set_new(o, "signature", json_string(sig));
    }
    if (ret == -1) {
        DEBUG(SSSDBG_OP_FAILURE, "json_object_set_new() failed.\n");
        return EINVAL;
    }

    *jws = o;

    return EOK;
}

errno_t verify_token(TALLOC_CTX *mem_ctx, struct devicecode_ctx *dc_data)
{
    int ret;
    json_t *keys;
    json_error_t json_error;
    json_t *jws = NULL;

    ret = get_jwks(mem_ctx, dc_data);
    if (ret != EOK) {
        talloc_free(dc_data->data);
        dc_data->data = NULL;
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read jwks file.\n");
        goto done;
    }

    keys = json_loads(dc_data->data, 0, &json_error);
    //talloc_free(dc_data->data);
    //dc_data->data = NULL;
    if (keys == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse jwk data from [%s] on line [%d]: [%s].\n",
              dc_data->jwks_uri, json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    if (dc_data->id_token_str != NULL) {
        ret = str_to_jws(dc_data, dc_data->id_token_str, &jws);
        if (!jose_jws_ver(NULL, jws, NULL, keys, false)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to verify id_token.\n");
        }

        dc_data->id_token_payload = jose_b64_dec_load(json_object_get(jws,
                                                                      "payload"));

        json_decref(jws);
    }
    if (dc_data->access_token_str != NULL) {
        ret = str_to_jws(dc_data, dc_data->access_token_str, &jws);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to convert access_token into jws.\n");
            dc_data->access_token_payload = NULL;
            ret = EOK;
            goto done;
        }
        if (!jose_jws_ver(NULL, jws, NULL, keys, false)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to verify access_token.\n");
        }

        dc_data->access_token_payload = jose_b64_dec_load(json_object_get(jws,
                                                                      "payload"));
    }

    /* Todo: verify content as well */
    ret = EOK;

done:
    json_decref(keys);
    talloc_free(dc_data->data);
    dc_data->data = NULL;

    return ret;
}

int get_json_integer(json_t *root, const char *attr)
{
    json_t *tmp;

    tmp = json_object_get(root, attr);
    if (!json_is_integer(tmp)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Result does not contain the '%s' interger.\n", attr);
        return -1;
    }

    return json_integer_value(tmp);
}

errno_t parse_openid_configuration(struct devicecode_ctx *dc_data)
{
    int ret;
    json_t *root = NULL;
    json_error_t json_error;

    root = json_loads(dc_data->data, 0, &json_error);
    if (root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse json data on line [%d]: [%s].\n",
              json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    ret = get_endpoints(root, dc_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get endpoints.\n");
        goto done;
    }

    talloc_free(dc_data->data);
    dc_data->data = NULL;

    ret = EOK;

done:
    json_decref(root);
    return ret;
}
errno_t parse_result(struct devicecode_ctx *dc_data)
{
    int ret;
    json_t *root = NULL;
    json_error_t json_error;

    root = json_loads(dc_data->data, 0, &json_error);
    if (root == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse json data on line [%d]: [%s].\n",
              json_error.line, json_error.text);
        ret = EINVAL;
        goto done;
    }

    dc_data->user_code = get_json_string(dc_data, root, "user_code");
    dc_data->device_code = get_json_string(dc_data, root, "device_code");
    dc_data->verification_uri = get_json_string(dc_data, root,
                                                "verification_uri");
    dc_data->verification_uri_complete = get_json_string(dc_data, root,
                                                   "verification_uri_complete");
    dc_data->message = get_json_string(dc_data, root, "message");
    dc_data->interval = get_json_integer(root, "interval");
    dc_data->expires_in = get_json_integer(root, "expires_in");

    dc_data->device_code_reply = talloc_strdup(dc_data, dc_data->data);
    if (dc_data->device_code_reply == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to copy device code reply.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    json_decref(root);
    return ret;
}

errno_t parse_token_result(struct devicecode_ctx *dc_data)
{
    json_t *tmp = NULL;
    json_error_t json_error;

    dc_data->result = json_loads(dc_data->data, 0, &json_error);
    if (dc_data->result == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to parse json data on line [%d]: [%s].\n",
              json_error.line, json_error.text);
        return EINVAL;
    }

    tmp = json_object_get(dc_data->result, "error");
    if (json_is_string(tmp)) {
        if (strcmp(json_string_value(tmp), "authorization_pending") == 0) {
            json_decref(dc_data->result);
            return EAGAIN;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Token request failed with [%s].\n",
                                     json_string_value(tmp));
            json_decref(dc_data->result);
            return EIO;
        }
    }

    /* Looks like we got the tokens */
    dc_data->access_token = json_object_get(dc_data->result, "access_token");
    dc_data->access_token_str = get_json_string(dc_data, dc_data->result,
                                                "access_token");
    dc_data->id_token = json_object_get(dc_data->result, "id_token");
    dc_data->id_token_str = get_json_string(dc_data, dc_data->result,
                                            "id_token");

    return EOK;
}

errno_t get_openid_configuration(struct devicecode_ctx *dc_ctx,
                                 const char *issuer_url)
{
    int ret;
    char *uri = NULL;
    bool has_slash = false;

    if (issuer_url[strlen(issuer_url) - 1] == '/') {
        has_slash = true;
    }

    uri = talloc_asprintf(dc_ctx, "%s%s.well-known/openid-configuration",
                                   issuer_url, has_slash ? "" : "/");
    if (uri == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for results.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = do_http_request(dc_ctx, uri, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "http request failed.\n");
    }

done:
    talloc_free(uri);

    return ret;
}

#define DEFAULT_SCOPE "user"

errno_t get_devicecode(TALLOC_CTX *mem_ctx,
                       struct devicecode_ctx *dc_data, const char *client_id)
{
    int ret;

    char *post_data = NULL;

    post_data  = talloc_asprintf(mem_ctx, "client_id=%s&scope=%s",
                                 client_id,
                                 dc_data->scope != NULL ? dc_data->scope
                                                        : DEFAULT_SCOPE);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for POST data.\n");
        return ENOMEM;
    }

    ret = do_http_request(dc_data, dc_data->device_authorization_endpoint,
                          post_data, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to send device code request.\n");
    }

    talloc_free(post_data);
    return ret;
}

errno_t get_token(TALLOC_CTX *mem_ctx,
                  struct devicecode_ctx *dc_data, const char *client_id,
                  const char *client_secret,
                  bool get_device_code)
{
    CURL *curl_ctx = NULL;
    CURLcode res;
    int ret;

    char *post_data;
    const char *post_data_tmpl = "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%s&device_code=%s";
    struct curl_slist *headers = NULL;

    headers = curl_slist_append(headers, "Accept: application/json");

    post_data = talloc_asprintf(mem_ctx, post_data_tmpl, client_id,
                                                         dc_data->device_code);
    if (post_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to generate POST data.\n");
        ret = ENOMEM;
        goto done;
    }

    if (client_secret != NULL) {
        post_data = talloc_asprintf_append(post_data, "&client_secret=%s",
                                           client_secret);
        if (post_data == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to add client secret to POST data.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    curl_ctx = curl_easy_init();
    if (curl_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize curl.\n");
        ret = EIO;
        goto done;
    }

    ret = set_http_opts(curl_ctx, dc_data, dc_data->token_endpoint, post_data,
                        NULL, headers);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to set http options.\n");
        goto done;
    }

    for (;;) {
        talloc_free(dc_data->data);
        dc_data->data = NULL;

        res = curl_easy_perform(curl_ctx);
        if (res != CURLE_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to send token request.\n");
            ret = EIO;
            goto done;
        }

        ret = parse_token_result(dc_data);
        if (ret != EAGAIN) {
            break;
        }

        /* only run once after getting the device code to tell the IdP we are
         * expecting that the user will connect */
        if (get_device_code) {
            /* TODO: check code */
            ret = EOK;
            break;
        }

        sleep(dc_data->interval);
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get token.\n");
    }

done:

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl_ctx);
    return ret;

}

errno_t get_userinfo(struct devicecode_ctx *dc_ctx)
{
    int ret;

    ret = do_http_request(dc_ctx, dc_ctx->userinfo_endpoint, NULL,
                          dc_ctx->access_token_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to send userinfo request.\n");
    }

    return ret;
}

#define IN_BUF_SIZE 4096
errno_t read_device_code_from_stdin(struct devicecode_ctx *dc_ctx)
{
    uint8_t buf[IN_BUF_SIZE];
    ssize_t len;
    errno_t ret;
    char *str;

    errno = 0;
    len = sss_atomic_read_s(STDIN_FILENO, buf, IN_BUF_SIZE);
    if (len == -1) {
        ret = errno;
        ret = (ret == 0) ? EINVAL: ret;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "read failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    if (len == 0 || *buf == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing device code\n");
        return EINVAL;
    }

    str = talloc_strndup(dc_ctx, (char *) buf, len);
    if (str == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
        return ENOMEM;
    }

    if (strlen(str) != len) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Input contains additional data, "
              "only JSON encoded device code expected.\n");
        talloc_free(str);
        return EINVAL;
    }

    talloc_free(dc_ctx->data);
    dc_ctx->data = str;

    DEBUG(SSSDBG_TRACE_ALL, "JSON device code: [%s].\n", dc_ctx->data);

    return EOK;
}

static const char *get_id_string(TALLOC_CTX *mem_ctx, json_t *id_object)
{
    switch (json_typeof(id_object)) {
    case JSON_STRING:
        return json_string_value(id_object);
        break;
    case JSON_INTEGER:
        return talloc_asprintf(mem_ctx, "%" JSON_INTEGER_FORMAT,
                                        json_integer_value(id_object));
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected user indentifier type.\n");
    }

    return NULL;
}

static const char *get_user_identifier(TALLOC_CTX *mem_ctx, json_t *userinfo,
                                      const char *user_identifier_attr)
{
    json_t *id_object = NULL;
    const char *user_identifier = NULL;

    if (user_identifier_attr != NULL) {
        id_object = json_object_get(userinfo, user_identifier_attr);
        if (id_object != NULL) {
            user_identifier = get_id_string(mem_ctx, id_object);
            if (user_identifier == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to get user identifier string.\n");
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to read attribute [%s] from userinfo data.\n",
                  user_identifier_attr);
        }
    } else {
        user_identifier = json_string_value(json_object_get(userinfo, "sub"));
        if (user_identifier == NULL) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Missing [sub] attribute, falling back to [id].\n");
            id_object = json_object_get(userinfo, "id");
            if (id_object != NULL) {
                user_identifier = get_id_string(mem_ctx, id_object);
                if (user_identifier == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "Failed to get user identifier string.\n");
                }
            } else {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to read attribute [id] from userinfo data.\n");
            }
        }
    }

    if (user_identifier == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No attribute to identify the user found.\n");
    } else {
        DEBUG(SSSDBG_CONF_SETTINGS, "User sub: [%s].\n", user_identifier);
    }

    return user_identifier;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int debug_fd = -1;
    const char *opt_logger = NULL;
    errno_t ret;
    json_error_t json_error;
    TALLOC_CTX *main_ctx = NULL;
    struct devicecode_ctx *dc_ctx;
    char *issuer_url = NULL;
    char *issuer = NULL;
    char *client_id = NULL;
    char *device_auth_endpoint = NULL;
    char *token_endpoint = NULL;
    char *userinfo_endpoint = NULL;
    char *jwks_uri = NULL;
    char *scope = NULL;
    char *client_secret = NULL;
    char *ca_db = NULL;
    char *user_identifier_attr = NULL;
    bool libcurl_debug = false;
    bool get_device_code = false;
    bool get_access_token = false;
    const char *user_identifier = NULL;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
        {"get-device-code", 0, POPT_ARG_NONE, NULL, 'a', _("Get device code and URL"), NULL},
        {"get-access-token", 0, POPT_ARG_NONE, NULL, 'b', _("Wait for access token"), NULL},
        {"issuer-url", 0, POPT_ARG_STRING, &issuer_url, 0, _("URL of Issuer IdP"), NULL},
        {"issuer", 0, POPT_ARG_STRING, &issuer, 0, _("Name of an IdP from the issuer file"), NULL},
        {"device-auth-endpoint", 0, POPT_ARG_STRING, &device_auth_endpoint, 0, _("Device authorization endpoint of the IdP"), NULL},
        {"token-endpoint", 0, POPT_ARG_STRING, &token_endpoint, 0, _("Token endpoint of the IdP"), NULL},
        {"userinfo-endpoint", 0, POPT_ARG_STRING, &userinfo_endpoint, 0, _("Userinfo endpoint of the IdP"), NULL},
        {"user-identifier-attribute", 0, POPT_ARG_STRING, &user_identifier_attr, 0, _("Unique identifier of the user in the userinfo data"), NULL},
        {"jwks-uri", 0, POPT_ARG_STRING, &jwks_uri, 0, _("JWKS URI of the IdP"), NULL},
        {"scope", 0, POPT_ARG_STRING, &scope, 0, _("Supported scope of the IdP to get userinfo"), NULL},
        {"client-id", 0, POPT_ARG_STRING, &client_id, 0, _("Client ID"), NULL},
        {"client-secret", 0, POPT_ARG_STRING, &client_secret, 0, _("Client secret (if needed)"), NULL},
        {"ca-db", 0, POPT_ARG_STRING, &ca_db, 0, _("Path to PEM file with CA certificates"), NULL},
        {"libcurl-debug", 0, POPT_ARG_NONE, NULL, 'c', _("Enable libcurl debug output"), NULL},
        SSSD_LOGGER_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    /*
     * This child can run as root or as sssd user relying on policy kit to
     * grant access to pcscd. This means that no setuid or setgid bit must be
     * set on the binary. We still should make sure to run with a restrictive
     * umask but do not have to make additional precautions like clearing the
     * environment. This would allow to use e.g. pkcs11-spy.so for further
     * debugging.
     */
    umask(SSS_DFL_UMASK);

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        case 'a':
            get_device_code = true;
            break;
        case 'b':
            get_access_token = true;
            break;
        case 'c':
            libcurl_debug = true;
            break;
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            _exit(-1);
        }
    }

    if (!get_device_code && !get_access_token) {
        fprintf(stderr,
                "\n--get-device-code or --get-access-token must be given.\n\n");
        poptPrintUsage(pc, stderr, 0);
        poptFreeContext(pc);
        _exit(-1);
    }

    if (get_device_code && get_access_token) {
        fprintf(stderr,
                "\n--get-device-code and --get-access-token are mutually exclusive .\n\n");
        poptPrintUsage(pc, stderr, 0);
        poptFreeContext(pc);
        _exit(-1);
    }

    if ((issuer_url != NULL && (issuer != NULL
                                || device_auth_endpoint != NULL
                                || token_endpoint != NULL))
        || (issuer != NULL && (issuer_url != NULL
                                || device_auth_endpoint != NULL
                                || token_endpoint != NULL))
        || (device_auth_endpoint != NULL && token_endpoint != NULL
                           && (issuer_url != NULL || issuer != NULL))
        || (issuer_url == NULL && issuer == NULL
                && ((device_auth_endpoint != NULL && token_endpoint == NULL)
                   || (device_auth_endpoint == NULL && token_endpoint != NULL)))
        || (issuer_url == NULL && issuer == NULL
                && (device_auth_endpoint == NULL || token_endpoint == NULL))) {
        fprintf(stderr, "\n--issuer-url or --issuer or --device-auth-endpoint "
                        "together with --token-endpoint are mutually exclusive "
                        "but one variant must be given.\n\n");
        poptPrintUsage(pc, stderr, 0);
        poptFreeContext(pc);
        _exit(-1);
    }

    if (client_id == NULL) {
        fprintf(stderr, "\n--client must be given.\n\n");
        poptPrintUsage(pc, stderr, 0);
        poptFreeContext(pc);
        _exit(-1);
    }

    poptFreeContext(pc);

    debug_prg_name = talloc_asprintf(NULL, "oidc_child[%d]", getpid());
    if (debug_prg_name == NULL) {
        ERROR("talloc_asprintf failed.\n");
        goto fail;
    }

    if (debug_fd != -1) {
        opt_logger = sss_logger_str[FILES_LOGGER];
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            opt_logger = sss_logger_str[STDERR_LOGGER];
            ERROR("set_debug_file_from_fd failed.\n");
        }
    }

    DEBUG_INIT(debug_level, opt_logger);

    DEBUG(SSSDBG_TRACE_FUNC, "oidc_child started.\n");

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Running with effective IDs: [%"SPRIuid"][%"SPRIgid"].\n",
          geteuid(), getegid());

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Running with real IDs [%"SPRIuid"][%"SPRIgid"].\n",
          getuid(), getgid());

    main_ctx = talloc_new(NULL);
    if (main_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        talloc_free(discard_const(debug_prg_name));
        goto fail;
    }
    talloc_steal(main_ctx, debug_prg_name);

    dc_ctx = talloc_zero(main_ctx, struct devicecode_ctx);
    if (dc_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for results.\n");
        ret = ENOMEM;
        goto fail;
    }
    dc_ctx->libcurl_debug = libcurl_debug;
    if (ca_db != NULL) {
        dc_ctx->ca_db = talloc_strdup(dc_ctx, ca_db);
        if (dc_ctx->ca_db == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy CA DB path.\n");
            ret = ENOMEM;
            goto fail;
        }
    }

    if (issuer_url != NULL) {
        ret = get_openid_configuration(dc_ctx, issuer_url);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get openid configuration.\n");
            goto fail;
        }

        ret = parse_openid_configuration(dc_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to parse openid configuration.\n");
            goto fail;
        }
    } else if (issuer != NULL) {
        ret = get_issuer(dc_ctx, issuer);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get issuer configuration.\n");
            goto fail;
        }
    } else if (device_auth_endpoint != NULL && token_endpoint != NULL) {
        ret = set_endpoints(dc_ctx, device_auth_endpoint, token_endpoint,
                            userinfo_endpoint, jwks_uri, scope);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set endpoints.\n");
            goto fail;
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing issuer information.\n");
        ret = EINVAL;
        goto fail;
    }

    if (get_device_code) {
        ret = get_devicecode(main_ctx, dc_ctx, client_id);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get device code.\n");
            goto fail;
        }
    }

    if (get_access_token) {
        if (dc_ctx->device_code == NULL) {
            ret = read_device_code_from_stdin(dc_ctx);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to read device code from stdin.\n");
                goto fail;
            }
        }
    }

    ret = parse_result(dc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to parse device code reply.\n");
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_ALL, "user_code: [%s].\n", dc_ctx->user_code);
    DEBUG(SSSDBG_TRACE_ALL, "device_code: [%s].\n",
                            dc_ctx->device_code);
    DEBUG(SSSDBG_TRACE_ALL, "verification_uri: [%s].\n",
                            dc_ctx->verification_uri);
    DEBUG(SSSDBG_TRACE_ALL, "verification_uri_complete: [%s].\n",
                            dc_ctx->verification_uri_complete == NULL ? "-"
                                           : dc_ctx->verification_uri_complete);
    DEBUG(SSSDBG_TRACE_ALL, "expires_in: [%d].\n", dc_ctx->expires_in);
    DEBUG(SSSDBG_TRACE_ALL, "interval: [%d].\n", dc_ctx->interval);
    DEBUG(SSSDBG_TRACE_ALL, "message: [%s].\n", dc_ctx->message);

    ret = get_token(main_ctx, dc_ctx, client_id, client_secret,
                    get_device_code);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get user token.\n");
        goto fail;
    }

    if (get_device_code) {
        /* TODO: currently this reply is used as RADIUS State and hence must
         * be not longer than 253 characters. Fix ipa-otpd to keep running and
         * use random State.
        fprintf(stdout,"%s\n", dc_ctx->device_code_reply);
         */
        fprintf(stdout,
                "{\"device_code\":\"%s\",\"expires_in\":%d,\"interval\":%d}\n",
                dc_ctx->device_code, dc_ctx->expires_in, dc_ctx->interval);
        fprintf(stdout,
                /* TODO: switch to completely generate pa data */
                "oauth2 {\"verification_uri\": \"%s\", \"user_code\": \"%s%s%s\"}\n",
                dc_ctx->verification_uri, dc_ctx->user_code,
                dc_ctx->verification_uri_complete == NULL ? ""
                                      : "\", \"verification_uri_complete\": \"",
                dc_ctx->verification_uri_complete == NULL ? ""
                                           : dc_ctx->verification_uri_complete);
        fflush(stdout);
    }

    if (get_access_token) {
        DEBUG(SSSDBG_TRACE_ALL, "access_token: [%s].\n",
                                dc_ctx->access_token_str);
        DEBUG(SSSDBG_TRACE_ALL, "id_token: [%s].\n", dc_ctx->id_token_str);

        if (dc_ctx->jwks_uri != NULL) {
            ret = verify_token(main_ctx, dc_ctx);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to verify tokens.\n");
                goto fail;
            }
        }

        talloc_free(dc_ctx->data);
        dc_ctx->data = NULL;
        ret = get_userinfo(dc_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get userinfo.\n");
            goto fail;
        }

        dc_ctx->userinfo = json_loads(dc_ctx->data, 0, &json_error);
        if (dc_ctx->userinfo == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to parse userinfo data on line [%d]: [%s].\n",
                  json_error.line, json_error.text);
            ret = EINVAL;
            goto fail;
        }

        if (dc_ctx->access_token_payload != NULL) {
            DEBUG(SSSDBG_TRACE_ALL, "access_token payload: [%s].\n",
                  json_dumps(dc_ctx->access_token_payload, 0));

            DEBUG(SSSDBG_CONF_SETTINGS, "User Principal: [%s].\n", json_string_value(json_object_get(dc_ctx->access_token_payload, "upn")));
            DEBUG(SSSDBG_CONF_SETTINGS, "User oid: [%s].\n", json_string_value(json_object_get(dc_ctx->access_token_payload, "oid")));
            DEBUG(SSSDBG_CONF_SETTINGS, "User sub: [%s].\n", json_string_value(json_object_get(dc_ctx->access_token_payload, "sub")));
        }

        if (dc_ctx->id_token_payload != NULL) {
            DEBUG(SSSDBG_TRACE_ALL, "id_token payload: [%s].\n",
                  json_dumps(dc_ctx->id_token_payload, 0));

            DEBUG(SSSDBG_CONF_SETTINGS, "User Principal: [%s].\n", json_string_value(json_object_get(dc_ctx->id_token_payload, "upn")));
            DEBUG(SSSDBG_CONF_SETTINGS, "User oid: [%s].\n", json_string_value(json_object_get(dc_ctx->id_token_payload, "oid")));
            DEBUG(SSSDBG_CONF_SETTINGS, "User sub: [%s].\n", json_string_value(json_object_get(dc_ctx->id_token_payload, "sub")));
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "userinfo: [%s].\n",
                                    json_dumps(dc_ctx->userinfo, 0));
#if 0
        DEBUG(SSSDBG_CONF_SETTINGS, "User sub: [%s].\n",
                   json_string_value(json_object_get(dc_ctx->userinfo, "sub")));

        fprintf(stdout,"%s",
                json_string_value(json_object_get(dc_ctx->userinfo, "sub")));
#endif

        user_identifier = get_user_identifier(dc_ctx, dc_ctx->userinfo,
                                              user_identifier_attr);
        if (user_identifier == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get user identifier.\n");
            ret = EINVAL;
            goto fail;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "User identifier: [%s].\n",
                                    user_identifier);

        fprintf(stdout,"%s", user_identifier);
        fflush(stdout);
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "oidc_child finished successful!\n");
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    curl_global_cleanup();
    return EXIT_SUCCESS;

fail:
    DEBUG(SSSDBG_CRIT_FAILURE, "oidc_child failed!\n");
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    curl_global_cleanup();
    return EXIT_FAILURE;
}
