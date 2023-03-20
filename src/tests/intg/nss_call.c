#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <stdlib.h>
#include <nss.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>



#define NSSRET(r) return (((r) == 0) ? NSS_STATUS_SUCCESS : NSS_STATUS_NOTFOUND )

enum nss_status _nss_call_getpwnam_r(const char *name, struct passwd *result,
                                     char *buffer, size_t buflen, int *errnop)
{
    struct passwd *res;
    int ret = getpwnam_r(name, result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_getpwuid_r(uid_t uid, struct passwd *result,
                                     char *buffer, size_t buflen, int *errnop)
{
    struct passwd *res;
    int ret = getpwuid_r(uid, result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_setpwent(void)
{
    setpwent();
}

enum nss_status _nss_call_getpwent_r(struct passwd *result,
                                    char *buffer, size_t buflen,
                                    int *errnop)
{
    struct passwd *res;
    int ret = getpwent_r(result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_endpwent(void)
{
    endpwent();
}

enum nss_status _nss_call_getgrnam_r(const char *name, struct group *result,
                                     char *buffer, size_t buflen, int *errnop)
{
    struct group *res;
    int ret = getgrnam_r(name, result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_getgrgid_r(gid_t gid, struct group *result,
                                     char *buffer, size_t buflen, int *errnop)
{
    struct group *res;
    int ret = getgrgid_r(gid, result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_setgrent(void)
{
    setgrent();
}

enum nss_status _nss_call_getgrent_r(struct group *result,
                                    char *buffer, size_t buflen, int *errnop)
{
    struct group *res;
    int ret = getgrent_r(result, buffer, buflen, &res);
    NSSRET(ret);
}

enum nss_status _nss_call_endgrent(void)
{
    endgrent();
}

enum nss_status _nss_call_initgroups_dyn(const char *user, gid_t group,
                                         long int *start, long int *size,
                                         gid_t **groups, long int limit,
                                         int *errnop)
{
    int ngroups = 0;
    gid_t *grps = NULL;
    long int max_ret;
    long int i;
    int ret;

    ret = getgrouplist(user, group, grps, &ngroups);
    if (ret != -1) {
        return NSS_STATUS_UNAVAIL;
     }

    grps = malloc(ngroups * sizeof(gid_t));
    if (grps == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    max_ret = ngroups;
    /* check we have enough space in the buffer */
    if ((*size - *start) < ngroups) {
        long int newsize;
        gid_t *newgroups;

        newsize = *size + ngroups;
        if ((limit > 0) && (newsize > limit)) {
            newsize = limit;
            max_ret = newsize - *start;
        }

        newgroups = (gid_t *)realloc((*groups), newsize * sizeof(**groups));
        if (!newgroups) {
            free(grps);
            return NSS_STATUS_UNAVAIL;
        }
        *groups = newgroups;
        *size = newsize;
    }

    for (i = 0; i < max_ret; i++) {
        (*groups)[*start] = grps[i];
        *start += 1;
    }
    free(grps);

    return NSS_STATUS_SUCCESS;
}
