/*
 * (C) 2005-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
 *                  Harald Welte <laforge@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <libnfnetlink/libnfnetlink.h>
#include "libnetfilter_conntrack.h"
#include "internal/internal.h"

/**
 * \defgroup LibrarySetup Library setup
 * @{
 */

/**
 * nfct_open - open a ctnetlink handler
 * \param subsys_id can be NFNL_SUBSYS_CTNETLINK or NFNL_SUBSYS_CTNETLINK_EXP
 * \param subscriptions ctnetlink groups to subscribe to events
 *
 * This function returns a handler to send commands to and receive replies from
 * kernel-space. You can pass the following subsystem IDs:
 *
 * - NFNL_SUBSYS_CTNETLINK: if you are only interested in conntrack operations
 * (excluding expectations).
 * - NFNL_SUBSYS_CTNETLINK_EXP: if you are only interested in expectation
 * operations (exclude conntracks).
 * - NFNL_SUBSYS_NONE: if you are interested in both conntrack and expectation
 * operations.
 *
 * On error, NULL is returned and errno is explicitly set.
 */

struct nfct_handle *nfct_open()
{
    struct nfnl_handle *nfnlh = nfnl_open();
    struct nfct_handle *nfcth = NULL;

    if (!nfnlh) return NULL;

    nfcth = malloc(sizeof(struct nfct_handle));
    if (!nfcth) goto err;
    /*init*/
    memset(nfcth, 0, sizeof(struct nfct_handle));
    nfcth->nfnlh = nfnlh;
    /*subsys open*/
    nfcth->nfnlssh_ct = nfnl_subsys_open(nfcth->nfnlh, NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_MAX, 0);
    if (!nfcth->nfnlssh_ct) goto err;
    /*return*/
    return nfcth;

err:
    if (nfnlh) nfnl_close(nfnlh);
    /*free nfct*/
    if (nfcth && nfcth->nfnlssh_ct)
    {
        nfnl_subsys_close(nfcth->nfnlssh_ct);
        nfcth->nfnlssh_ct = NULL;
    }
    if(nfcth) free(nfcth);
    /*return*/
    return NULL;
}

/**
 * nfct_close - close a ctnetlink handler
 * \param cth handler obtained via nfct_open()
 *
 * This function returns -1 on error and errno is explicitly set.
 */
int nfct_close(struct nfct_handle *cth)
{
    int err;
    if (cth->nfnlssh_ct)
    {
        nfnl_subsys_close(cth->nfnlssh_ct);
        cth->nfnlssh_ct = NULL;
    }

    /* required by the new API */
    cth->cb = NULL;
    cth->cb2 = NULL;
    free(cth->nfnl_cb_ct.data);

    cth->nfnl_cb_ct.call = NULL;
    cth->nfnl_cb_ct.data = NULL;
    cth->nfnl_cb_ct.attr_count = 0;

    err = nfnl_close(cth->nfnlh);
    free(cth);

    return err;
}

/**
 * nfct_fd - get the Netlink file descriptor of one existing ctnetlink handler
 * \param cth handler obtained via nfct_open()
 */
int nfct_fd(struct nfct_handle *cth)
{
    return nfnl_fd(cth->nfnlh);
}

const struct nfnl_handle *nfct_nfnlh(struct nfct_handle *cth)
{
    return cth->nfnlh;
}

/**
 * @}
 */

void __noreturn __abi_breakage(const char *file, int line, const char *reason)
{
    fprintf(stderr, "ctnetlink kernel ABI is broken, contact your vendor.\n"
                    "%s:%d reason: %s\n", file, line, reason);
    exit(EXIT_FAILURE);
}
