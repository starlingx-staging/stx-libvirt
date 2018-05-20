/*
 * virresctrl.c: methods for managing resource control
 *
 * Copyright (C) 2017 Intel, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *  Eli Qiao <liyong qiao intel com>
 */

#include <config.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virresctrl.h"
#include "virstring.h"
#include "viruuid.h"

VIR_LOG_INIT("util.resctrl");

#define VIR_FROM_THIS VIR_FROM_RESCTRL
#define SYSFS_RESCTRL_PATH "/sys/fs/resctrl"
#define VIR_RESCTRL_LOCK(fd, op) flock(fd, op)
#define VIR_RESCTRL_UNLOCK(fd) flock(fd, LOCK_UN)
#define CONSTRUCT_RESCTRL_PATH(domain_name, item_name) \
do { \
    if (NULL == domain_name) { \
        if (virAsprintf(&path, "%s/%s", SYSFS_RESCTRL_PATH, item_name) < 0) \
            return -1; \
    } else { \
        if (virAsprintf(&path, "%s/%s/%s", SYSFS_RESCTRL_PATH, domain_name, \
                        item_name) < 0) \
            return -1;  \
    } \
} while (0)

VIR_ENUM_IMPL(virResctrl, VIR_RESCTRL_TYPE_LAST,
              "L3",
              "L3CODE",
              "L3DATA")

/**
 * a virResctrlGroup represents a resource control group, it's a directory
 * under /sys/fs/resctrl.
 * e.g. /sys/fs/resctrl/CG1
 * |-- cpus
 * |-- schemata
 * `-- tasks
 * # cat schemata
 * L3DATA:0=fffff;1=fffff
 * L3CODE:0=fffff;1=fffff
 *
 * Besides, it can also represent the default resource control group of the
 * host.
 */

typedef struct _virResctrlGroup virResctrlGroup;
typedef virResctrlGroup *virResctrlGroupPtr;
struct _virResctrlGroup {
    char *name; /* resource group name, NULL for default host group */
    size_t n_tasks; /* number of tasks assigned to the resource group */
    char **tasks; /* task id list */
    virResctrlSchemataPtr schemata[VIR_RESCTRL_TYPE_LAST]; /* Array for schemata */
};

/* All resource control groups on this host, including default resource group */
typedef struct _virResctrlHost virResctrlHost;
typedef virResctrlHost *virResctrlHostPtr;
struct _virResctrlHost {
    size_t n_groups; /* number of resource control group */
    virResctrlGroupPtr *groups; /* list of resource control group */
};

void
virResctrlFreeSchemata(virResctrlSchemataPtr ptr)
{
    size_t i;

    if (!ptr)
        return;

    VIR_DEBUG("resctrl free schemata %p", ptr);

    for (i = 0; i < ptr->n_masks; i++) {
        virBitmapFree(ptr->masks[i]->mask);
        VIR_FREE(ptr->masks[i]);
    }

    VIR_FREE(ptr);
    ptr = NULL;
}

static void
virResctrlFreeGroup(virResctrlGroupPtr ptr)
{
    size_t i;

    if (!ptr)
        return;

    VIR_DEBUG("resctrl free group '%s'", ptr->name);

    for (i = 0; i < ptr->n_tasks; i++)
        VIR_FREE(ptr->tasks[i]);
    VIR_FREE(ptr->name);

    for (i = 0; i < VIR_RESCTRL_TYPE_LAST; i++)
        virResctrlFreeSchemata(ptr->schemata[i]);

    VIR_FREE(ptr);
    ptr = NULL;
}

/* Return specify type of schemata string from schematalval.
   e.g., 0=f;1=f */
static int
virResctrlGetSchemataString(virResctrlType type,
                            const char *schemataval,
                            char **schematastr)
{
    int rc = -1;
    char *prefix = NULL;
    char **lines = NULL;

    VIR_DEBUG("resctrl get schemata string from '%s'", schemataval);

    if (virAsprintf(&prefix,
                    "%s:",
                    virResctrlTypeToString(type)) < 0)
        return rc;

    lines = virStringSplit(schemataval, "\n", 0);

    if (VIR_STRDUP(*schematastr,
                   virStringListGetFirstWithPrefix(lines, prefix)) < 0)
        goto cleanup;

    if (*schematastr == NULL)
        rc = -1;
    else
        rc = 0;

 cleanup:
    VIR_FREE(prefix);
    virStringListFree(lines);
    return rc;
}

static int
virResctrlRemoveSysGroup(const char* name)
{
    char *path = NULL;
    int ret = -1;

    VIR_DEBUG("resctrl remove sys group '%s'", name);

    if (virAsprintf(&path, "%s/%s", SYSFS_RESCTRL_PATH, name) < 0)
        return ret;

    ret = rmdir(path);
    VIR_FREE(path);
    return ret;
}

static int
virResctrlNewSysGroup(const char *name)
{
    char *path = NULL;
    int ret = -1;
    mode_t mode = 0755;

    VIR_DEBUG("resctrl new sys group '%s'", name);

    if (virAsprintf(&path, "%s/%s", SYSFS_RESCTRL_PATH, name) < 0)
        return ret;

    if (!virFileExists(path)) {
        if (virDirCreate(path, mode, 0, 0, 0) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, 
                           _("error creating directory for resctrl group '%s'"), name);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    VIR_FREE(path);
    return ret;
}

static int
virResctrlWrite(const char *name, const char *item, const char *content)
{
    char *path;
    int writefd;
    int rc = -1;

    CONSTRUCT_RESCTRL_PATH(name, item);

    VIR_DEBUG("resctrl write '%s' to '%s'", content, name);

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("resctrl file '%s' does not exist"), path);
        goto cleanup;
    }

    if ((writefd = open(path, O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("error opening resctrl file '%s'"), path);
        goto cleanup;
    }

    if (safewrite(writefd, content, strlen(content)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("error writing to resctrl file '%s'"), path);
        goto cleanup;
    }

    rc = 0;

 cleanup:
    VIR_FREE(path);
    VIR_FORCE_CLOSE(writefd);
    return rc;
}

static
virBitmapPtr virResctrlMask2Bitmap(const char *mask, size_t size)
{
    virBitmapPtr bitmap;
    unsigned int tmp;
    size_t i;

    VIR_DEBUG("resctrl mask 2 bitmap '%s'", mask);

    if (virStrToLong_ui(mask, NULL, 16, &tmp) < 0) {
        VIR_WARN("failed to parse schemata mask '%s'", mask);
        return NULL;
    }

    bitmap = virBitmapNewEmpty();

    for (i = 0; i < size; i++) {
        if (((tmp & 0x1) == 0x1) &&
                (virBitmapSetBitExpand(bitmap, i) < 0)) {
            VIR_WARN("failed to set bit for schemata mask '%s'", mask);
            goto error;
        }
        tmp = tmp >> 1;
    }

    return bitmap;

 error:
    virBitmapFree(bitmap);
    return NULL;
}

char *virResctrlBitmap2String(virBitmapPtr bitmap)
{
    char *tmp;
    char *ret = NULL;
    char *p;

    tmp = virBitmapString(bitmap);

    VIR_DEBUG("resctrl bitmap 2 string '%s'", tmp);

    /* skip "0x" */
    p = tmp + 2;

    /* first non-0 position */
    while (*++p == '0');

    if (VIR_STRDUP(ret, p) < 0)
        ret = NULL;

    VIR_FREE(tmp);
    return ret;
}

static int
virResctrlParseSchemata(const char* schemata_str,
                        virResctrlSchemataPtr schemata)
{
    int ret = -1;
    size_t i, size;
    virResctrlMaskPtr mask;
    char **schemata_list;
    char *mask_str;

    VIR_DEBUG("resctrl parse schemata string '%s'", schemata_str);

    /* parse 0=fffff;1=f */
    schemata_list = virStringSplit(schemata_str, ";", 0);

    if (!schemata_list)
        goto cleanup;

    for (i = 0; schemata_list[i] != NULL; i++) {
        /* parse 0=fffff */
        mask_str = strchr(schemata_list[i], '=') + 1;

        if (!mask_str)
            goto cleanup;

        if (VIR_ALLOC(mask) < 0)
            goto cleanup;

        mask->cache_id = i;
        size = strlen(mask_str) * 4; 
        mask->mask = virResctrlMask2Bitmap(mask_str, size);
        schemata->n_masks += 1;
        schemata->masks[i] = mask;

    }
    ret = 0;

 cleanup:
    virStringListFree(schemata_list);
    return ret;
}

static int
virResctrlLoadGroup(const char *name,
                    virResctrlHostPtr host)
{
    char *schemataval = NULL;
    char *schemata_str = NULL;
    virResctrlType i;
    int rv;
    virResctrlGroupPtr grp;
    virResctrlSchemataPtr schemata;

    VIR_DEBUG("resctrl load group '%s'", name ? name : "default");

    rv = virFileReadValueString(&schemataval,
                                SYSFS_RESCTRL_PATH "/%s/schemata",
                                name ? name : "");

    if (rv < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, 
                       _("error reading resctrl schemata file '%s'"), name);
        return rv;
    }

    if (VIR_ALLOC(grp) < 0)
        goto cleanup;

    if (VIR_STRDUP(grp->name, name) < 0)
        goto cleanup;

    for (i = 0; i < VIR_RESCTRL_TYPE_LAST; i++) {
        rv = virResctrlGetSchemataString(i, schemataval, &schemata_str);

        if (rv < 0)
            continue;

        if (VIR_ALLOC(schemata) < 0)
            goto cleanup;

        schemata->type = i;

        if (virResctrlParseSchemata(schemata_str, schemata) < 0) {
            VIR_FREE(schemata);
            VIR_FREE(schemata_str);
            goto cleanup;
        }

        grp->schemata[i] = schemata;
        VIR_FREE(schemata_str);
    }

    if (VIR_APPEND_ELEMENT(host->groups,
                           host->n_groups,
                           grp) < 0) {
        virResctrlFreeGroup(grp);
        goto cleanup;
    }

    rv = 0;

 cleanup:
    VIR_FREE(schemataval);
    return rv;
}

static int
virResctrlLoadHost(virResctrlHostPtr host)
{
    int rv = -1;
    DIR *dirp = NULL;
    char *path = NULL;
    struct dirent *ent;

    VIR_DEBUG("resctrl load host");

    rv = virDirOpen(&dirp, SYSFS_RESCTRL_PATH);
    if (rv < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, 
                       _("error opening resctrl dir '%s'"), SYSFS_RESCTRL_PATH);
        return rv;
    }

    /* load default group first */
    if (virResctrlLoadGroup(NULL, host) < 0) {
        VIR_DEBUG("failed to load default resctrl group"); 
        goto cleanup;
    }

    while ((rv = virDirRead(dirp, &ent, path)) > 0) {
        /* resctrl is not hierarchical, only read directory under
           /sys/fs/resctrl */

        if ((ent->d_type != DT_DIR) || STREQ(ent->d_name, "info"))
            continue;

        if (virResctrlLoadGroup(ent->d_name, host) < 0) {
            VIR_DEBUG("failed to load '%s' resctrl group", ent->d_name);
            goto cleanup;
        }
    }

    rv = 0;

cleanup:
    VIR_DIR_CLOSE(dirp);
    return rv;
}

static void
virResctrlRefreshHost(virResctrlHostPtr host, bool defrag)
{
    virResctrlGroupPtr default_grp = NULL;
    virResctrlSchemataPtr schemata = NULL;
    size_t i, j, k, num, offset;
    virResctrlType t;

    VIR_DEBUG("resctrl refresh host %s defragmentation", defrag ? "with" : "without");

    default_grp = host->groups[0];

    for (t = 0; t < VIR_RESCTRL_TYPE_LAST; t++) {
        if (default_grp->schemata[t] != NULL) {
            for (i = 0; i < default_grp->schemata[t]->n_masks; i++) {
                /* Reset default group's mask */
                VIR_DEBUG("resctrl refresh host: default mask of type '%s' before: '%s'", 
                           virResctrlTypeToString(default_grp->schemata[t]->type), 
                           virResctrlBitmap2String(default_grp->schemata[t]->masks[i]->mask));
                virBitmapSetAll(default_grp->schemata[t]->masks[i]->mask);
                /* Loop each other resource group except default group */
                offset = 0;
                for (j = 1; j < host->n_groups; j++) {
                    schemata = host->groups[j]->schemata[t];
                    /* Substact all used bits from default schemata */
                    if ((virBitmapSize(schemata->masks[i]->mask) <
                         virBitmapSize(default_grp->schemata[t]->masks[i]->mask)) ||
                        !virBitmapIsAllSet(schemata->masks[i]->mask)) {
                        /* Shift all the used bit in all the groups to the left */
                        if (defrag) {
                            VIR_DEBUG("resctrl refresh host: '%s' mask of type '%s' before: '%s'",
                                       host->groups[j]->name,
                                       virResctrlTypeToString(schemata->type),
                                       virResctrlBitmap2String(schemata->masks[i]->mask));
                            num = virBitmapCountBits(schemata->masks[i]->mask);
                            virBitmapClearAll(schemata->masks[i]->mask);
                            for (k = 0; k < num; k++) {
                                ignore_value(virBitmapSetBitExpand(schemata->masks[i]->mask, k + offset));
                            }
                            offset += num;
                            VIR_DEBUG("resctrl refresh host: '%s' mask of type '%s' after: '%s'",
                                       host->groups[j]->name,
                                       virResctrlTypeToString(schemata->type),
                                       virResctrlBitmap2String(schemata->masks[i]->mask));
                        }
                        /* Substact all used bits from default schemata */
                        virBitmapSubtract(default_grp->schemata[t]->masks[i]->mask,
                                          schemata->masks[i]->mask);
                    }
                }
                VIR_DEBUG("resctrl refresh host: default mask of type '%s' after: '%s'",
                           virResctrlTypeToString(default_grp->schemata[t]->type),
                           virResctrlBitmap2String(default_grp->schemata[t]->masks[i]->mask));
            }
        }
    }
}

static virResctrlHostPtr
virResctrlGetHost(bool update)
{
    virResctrlHostPtr host = NULL;

    VIR_DEBUG("resctrl get host");

    if (VIR_ALLOC(host) < 0)
        return NULL;

    if (virResctrlLoadHost(host) < 0) {
        VIR_DEBUG("failed to load resctrl host");
        return NULL;
    }

    virResctrlRefreshHost(host, update);

    return host;
}

static virResctrlGroupPtr
virResctrlGetFreeGroup(void)
{
    size_t i;
    virResctrlHostPtr host = NULL;
    virResctrlGroupPtr grp = NULL;

    VIR_DEBUG("resctrl get free group");

    if ((host = virResctrlGetHost(false)) == NULL) {
        VIR_DEBUG("failed to get resctrl host");
        return NULL;
    }

    for (i = 1; i < host->n_groups; i++)
        virResctrlFreeGroup(host->groups[i]);

    grp = host->groups[0];
    VIR_FREE(host);

    return grp;
}

virResctrlSchemataPtr
virResctrlGetFreeCache(virResctrlType type)
{
    virResctrlType t;
    virResctrlGroupPtr grp = NULL;
    virResctrlSchemataPtr schemata = NULL;
    int lockfd = -1;

    VIR_DEBUG("resctrl get free cache");

    lockfd = open(SYSFS_RESCTRL_PATH, O_DIRECTORY);
    if (lockfd < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, 
                       _("error getting lock on resctrl dir"));
        return NULL;
    }

    VIR_RESCTRL_LOCK(lockfd, LOCK_SH);

    if ((grp = virResctrlGetFreeGroup()) == NULL) {
        VIR_DEBUG("failed to get free resctrl group");
        goto cleanup;
    }

    for (t = 0; t < VIR_RESCTRL_TYPE_LAST; t++) {
        if (t == type)
            schemata = grp->schemata[t];
        else
            virResctrlFreeSchemata(grp->schemata[t]);
    }

 cleanup:
    VIR_RESCTRL_UNLOCK(lockfd);
    VIR_FORCE_CLOSE(lockfd);
    return schemata;
}

static int
virResctrlCalculateCbm(int cbm_len,
                       virBitmapPtr defaultcbm,
                       virBitmapPtr newcbm)
{
    ssize_t pos = -1;
    size_t i;

    VIR_DEBUG("resctrl calculate cbm of length %d from default '%s'", 
               cbm_len, virResctrlBitmap2String(defaultcbm));

    /* not enough cache way to be allocated */
    if (virBitmapCountBits(defaultcbm) < cbm_len + 1) {
        VIR_DEBUG("not enough bits left to fulfill resctrl request"); 
        return -1;
    }

    while ((pos = virBitmapNextSetBit(defaultcbm, pos)) >= 0) {
        for (i = 0; i < cbm_len; i++)
            ignore_value(virBitmapSetBitExpand(newcbm, i + pos));
        /* Test if newcbm is sub set of defaultcbm */
        if (virBitmapNextClearBit(defaultcbm, pos) > i + pos) {
            break;
        } else {
            pos = pos + i - 1;
            virBitmapClearAll(newcbm);
        }
    }

    if (virBitmapCountBits(newcbm) != cbm_len) {
        VIR_DEBUG("cbm cannot be calculated for resctrl request");
        return -1;
    }

    /* consume default cbm after allocation */
    virBitmapSubtract(defaultcbm, newcbm);

    VIR_DEBUG("new resctrl cbm is '%s'", virResctrlBitmap2String(newcbm));

    return 0;
}

/* Fill mask value for newly created resource group base on hostcachebank
 * and domcachebank */
static int
virResctrlFillMask(virResctrlGroupPtr grp,
                  virResctrlGroupPtr free_grp,
                  virResctrlCachetunePtr cachetune)
{
    unsigned int cache_id;
    unsigned int cache_type;
    int cbm_candidate_len;
    virResctrlSchemataPtr schemata;
    virResctrlMaskPtr mask;

    VIR_DEBUG("resctrl fill mask");

    cache_type = cachetune->type;
    cache_id = cachetune->cache_id;
    schemata = grp->schemata[cache_type];

    if ((schemata == NULL) && (VIR_ALLOC(schemata) < 0))
        return -1;

    if (VIR_ALLOC(mask) < 0)
        return -1;

    mask->cache_id = cache_id;
    /* here should be control->granularity and control->min
       also domcachebank size should be checked while define domain xml */
    cbm_candidate_len = cachetune->size / cachetune->granularity;
    if (cachetune->size % cachetune->granularity != 0)
        cbm_candidate_len += 1;
    mask->mask = virBitmapNew(cbm_candidate_len);

    if (virResctrlCalculateCbm(cbm_candidate_len,
                               free_grp->schemata[cache_type]->masks[cache_id]->mask,
                               mask->mask) < 0) {
        VIR_DEBUG("failed to calclate cbm for '%s'", grp->name);
        goto error;
    }

    schemata->type = cache_type;
    schemata->n_masks += 1;
    schemata->masks[cache_id] = mask;
    grp->schemata[cache_type] = schemata;

    return 0;

 error:
    VIR_FREE(schemata);
    return -1;
}

static int
virResctrlCompleteMask(virResctrlSchemataPtr schemata,
                       virResctrlSchemataPtr defaultschemata)
{
    size_t i, size;
    virResctrlMaskPtr mask;

    VIR_DEBUG("resctrl complete mask");

    if (schemata == NULL && VIR_ALLOC(schemata) < 0)
        return -1;

    if (schemata->n_masks == defaultschemata->n_masks)
        return 0;

    for (i = 0; i < defaultschemata->n_masks; i++) {
        if (schemata->masks[i] == NULL) {
            if (VIR_ALLOC(mask) < 0)
                goto error;

            mask->cache_id = i;
            size = virBitmapLastSetBit(defaultschemata->masks[i]->mask) + 1;
            mask->mask = virBitmapNew(size);
            schemata->n_masks += 1;
            schemata->masks[i] = mask;
            /* resctrl doesn't allow mask to be zero
               use all the bits to fill up the cbm which
               domaincache bank doens't provide */
            virBitmapSetAll(mask->mask);
        }
    }

    return 0;

 error:
    VIR_FREE(schemata);
    return -1;
}

/* complete the schemata in the resrouce group before it can be write back
   to resctrl */
static int
virResctrlCompleteGroup(virResctrlGroupPtr grp,
                        virResctrlGroupPtr default_grp)
{
    virResctrlType t;
    virResctrlSchemataPtr schemata;
    virResctrlSchemataPtr defaultschemata;

    VIR_DEBUG("resctrl complete group");

    /* NOTES: resctrl system require we need provide all cache's cbm mask */
    for (t = 0; t < VIR_RESCTRL_TYPE_LAST; t++) {
        defaultschemata = default_grp->schemata[t];
        if (defaultschemata != NULL) {
            schemata = grp->schemata[t];
            if (virResctrlCompleteMask(schemata, defaultschemata) < 0)
                return -1;
        }
    }
    return 0;

}

static
char *virResctrlGetSchemataStr(virResctrlSchemataPtr schemata)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    VIR_DEBUG("resctrl get schemata string");

    virBufferAsprintf(&buf, "%s:%u=%s",
                      virResctrlTypeToString(schemata->type),
                      schemata->masks[0]->cache_id,
                      virResctrlBitmap2String(schemata->masks[0]->mask));

    for (i = 1; i < schemata->n_masks; i ++)
        virBufferAsprintf(&buf, ";%u=%s",
                          schemata->masks[i]->cache_id,
                          virResctrlBitmap2String(schemata->masks[i]->mask));

    return virBufferContentAndReset(&buf);
}

static int
virResctrlFlushGroup(virResctrlGroupPtr grp)
{
    int ret = -1;
    size_t i;
    char *schemata_str = NULL;
    virResctrlType t;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    VIR_DEBUG("resctrl flush group '%s'", grp->name ? grp->name : "default");

    if (grp->name != NULL && virResctrlNewSysGroup(grp->name) < 0) {
        VIR_WARN("failed to create new resctrl group '%s'", grp->name);
        return ret;
    }

    for (t = 0; t < VIR_RESCTRL_TYPE_LAST; t++) {
        if (grp->schemata[t] != NULL) {
            schemata_str = virResctrlGetSchemataStr(grp->schemata[t]);
            virBufferAsprintf(&buf, "%s\n", schemata_str);
            VIR_FREE(schemata_str);
        }
    }

    schemata_str = virBufferContentAndReset(&buf);

    if (virResctrlWrite(grp->name, "schemata", schemata_str) < 0) {
        VIR_WARN("failed to write resctrl schemata mask '%s' for group '%s'", schemata_str, grp->name);
        goto cleanup;
    }

    for (i = 0; i < grp->n_tasks; i++) {
        if (virResctrlWrite(grp->name, "tasks", grp->tasks[i]) < 0) {
            VIR_WARN("failed to write resctrl tasks for group '%s'", grp->name);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    VIR_FREE(schemata_str);
    return ret;
}

int virResctrlSetCachetunes(unsigned char* uuid,
                            virResctrlCachetunePtr cachetunes, size_t ncachetune,
                            pid_t *pids, size_t npid)
{
    size_t i;
    int ret = -1;
    char name[VIR_UUID_STRING_BUFLEN];
    char *tmp;
    int lockfd = -1;
    virResctrlGroupPtr grp = NULL;
    virResctrlGroupPtr default_grp = NULL;

    virUUIDFormat(uuid, name);

    VIR_DEBUG("resctrl set cachetunes for '%s'", name);

    if (ncachetune < 1)
        return 0;

    /* create new resource group */
    if (VIR_ALLOC(grp) < 0)
        goto error;

    if (VIR_STRDUP(grp->name, name) < 0)
        goto error;

    /* allocate file lock */
    lockfd = open(SYSFS_RESCTRL_PATH, O_DIRECTORY);
    if (lockfd < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("error getting lock on resctrl dir")); 
        goto error;
    }

    VIR_RESCTRL_LOCK(lockfd, LOCK_EX);

    if ((default_grp = virResctrlGetFreeGroup()) == NULL) {
        VIR_WARN("failed to get free resctrl group for '%s'", grp->name);
        goto error;
    }

    /* Allocate cache for each cache bank defined in cache tune */
    for (i = 0; i < ncachetune; i++) {
        /* fill up newly crated grp and consume from default_grp */
        if (virResctrlFillMask(grp, default_grp, &cachetunes[i]) < 0) {
            VIR_WARN("failed to fill resctrl mask for '%s'", grp->name);
            goto error;
        }
    }

    /* Add tasks to grp */
    for (i = 0; i < npid; i++) {
        if (virAsprintf(&tmp, "%llu", (long long)pids[i]) < 0) {
            VIR_WARN("failed to parse resctrl pid for '%s'", grp->name);
            goto error;
        }

        if (VIR_APPEND_ELEMENT(grp->tasks,
                               grp->n_tasks,
                               tmp) < 0) {
            VIR_WARN("failed to append resctrl pid for '%s'", grp->name);
            VIR_FREE(tmp);
            goto error;
        }
    }

    if (virResctrlCompleteGroup(grp, default_grp) < 0) {
        VIR_WARN("failed to complete resctrl group for '%s'", grp->name); 
        goto error;
    }

    if (virResctrlFlushGroup(grp) < 0) {
        VIR_WARN("failed to flush resctrl group for '%s'", grp->name);
        goto error;
    }

    if (virResctrlFlushGroup(default_grp) < 0) {
        VIR_WARN("failed to flush default resctrl group for '%s'", grp->name);
        virResctrlRemoveSysGroup(grp->name);
        goto error;
    }

    ret = 0;

 error:
    VIR_RESCTRL_UNLOCK(lockfd);
    VIR_FORCE_CLOSE(lockfd);
    virResctrlFreeGroup(grp);
    virResctrlFreeGroup(default_grp);
    return ret;
}

int virResctrlRemoveCachetunes(unsigned char* uuid)
{
    int ret = -1;
    int lockfd = -1;
    size_t i;
    char name[VIR_UUID_STRING_BUFLEN];
    virResctrlHostPtr host = NULL;

    virUUIDFormat(uuid, name);

    VIR_DEBUG("resctrl remove cachetunes for '%s'", name);

    lockfd = open(SYSFS_RESCTRL_PATH, O_DIRECTORY);
    if (lockfd < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("error getting lock on resctrl dir"));
        return ret;
    }

    VIR_RESCTRL_LOCK(lockfd, LOCK_SH);

    if (virResctrlRemoveSysGroup(name) < 0) {
        VIR_WARN("failed to remove resctrl group '%s'", name);
        goto cleanup;
    }

    if ((host = virResctrlGetHost(true)) == NULL) {
        VIR_WARN("failed to get resctrl host for '%s'", name);
        goto cleanup;
    }

    for (i = 0;  i < host->n_groups; i++) {
        if (virResctrlFlushGroup(host->groups[i]) < 0) {
            VIR_WARN("failed to flush resctrl group for '%s'", name);
        }
        virResctrlFreeGroup(host->groups[i]);
    }
    VIR_FREE(host);

 cleanup:
    VIR_RESCTRL_UNLOCK(lockfd);
    VIR_FORCE_CLOSE(lockfd);
    return ret;
}
