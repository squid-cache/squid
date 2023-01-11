/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_RADIX_H
#define SQUID_RADIX_H

/*
 * Copyright (c) 1988, 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)radix.h     8.2 (Berkeley) 10/31/94
 */

#undef RN_DEBUG
/*
 * Radix search tree node layout.
 */

struct squid_radix_node {

    struct squid_radix_mask *rn_mklist; /* list of masks contained in subtree */

    struct squid_radix_node *rn_p;  /* parent */
    short rn_b;         /* bit offset; -1-index(netmask) */
    char rn_bmask;      /* node: mask for bit test */
    unsigned char rn_flags; /* enumerated next */
#define RNF_NORMAL  1   /* leaf contains normal route */
#define RNF_ROOT    2   /* leaf is root leaf for tree */
#define RNF_ACTIVE  4   /* This node is alive (for rtfree) */

    union {

        struct {        /* leaf only data: */
            char *rn_Key;   /* object of search */
            char *rn_Mask;  /* netmask, if present */

            struct squid_radix_node *rn_Dupedkey;
        } rn_leaf;

        struct {        /* node only data: */
            int rn_Off;     /* where to start compare */

            struct squid_radix_node *rn_L;  /* progeny */

            struct squid_radix_node *rn_R;  /* progeny */
        } rn_node;
    } rn_u;
#ifdef RN_DEBUG

    int rn_info;

    struct squid_radix_node *rn_twin;

    struct squid_radix_node *rn_ybro;
#endif
};

#define rn_key rn_u.rn_leaf.rn_Key
#define rn_mask rn_u.rn_leaf.rn_Mask

/*
 * Annotations to tree concerning potential routes applying to subtrees.
 */

struct squid_radix_mask {
    short rm_b;         /* bit offset; -1-index(netmask) */
    char rm_unused;     /* cf. rn_bmask */
    unsigned char rm_flags; /* cf. rn_flags */

    struct squid_radix_mask *rm_mklist; /* more masks to try */
    union {
        char *rmu_mask;     /* the mask */

        struct squid_radix_node *rmu_leaf;  /* for normal routes */
    } rm_rmu;
    int rm_refs;        /* # of references to this struct */
};

struct squid_radix_node_head {

    struct squid_radix_node *rnh_treetop;
    int rnh_addrsize;       /* permit, but not require fixed keys */
    int rnh_pktsize;        /* permit, but not require fixed keys */

    struct squid_radix_node *(*rnh_addaddr) /* add based on sockaddr */
    (void *v, void *mask, struct squid_radix_node_head * head, struct squid_radix_node nodes[]);

    struct squid_radix_node *(*rnh_addpkt)  /* add based on packet hdr */
    (void *v, void *mask, struct squid_radix_node_head * head, struct squid_radix_node nodes[]);

    struct squid_radix_node *(*rnh_deladdr) /* remove based on sockaddr */
    (void *v, void *mask, struct squid_radix_node_head * head);

    struct squid_radix_node *(*rnh_delpkt)  /* remove based on packet hdr */
    (void *v, void *mask, struct squid_radix_node_head * head);

    struct squid_radix_node *(*rnh_matchaddr)       /* locate based on sockaddr */
    (void *v, struct squid_radix_node_head * head);

    struct squid_radix_node *(*rnh_lookup)  /* locate based on sockaddr */

    (void *v, void *mask, struct squid_radix_node_head * head);

    struct squid_radix_node *(*rnh_matchpkt)    /* locate based on packet hdr */
    (void *v, struct squid_radix_node_head * head);

    int (*rnh_walktree)     /* traverse tree */
    (struct squid_radix_node_head * head, int (*f) (struct squid_radix_node *, void *), void *w);

    struct squid_radix_node rnh_nodes[3];   /* empty tree for common case */
};

SQUIDCEXTERN void squid_rn_init (void);

SQUIDCEXTERN int squid_rn_inithead(struct squid_radix_node_head **, int);
SQUIDCEXTERN int squid_rn_refines(void *, void *);

SQUIDCEXTERN int squid_rn_walktree(struct squid_radix_node_head *, int (*)(struct squid_radix_node *, void *), void *);

SQUIDCEXTERN struct squid_radix_node *squid_rn_addmask(void *, int, int);

SQUIDCEXTERN struct squid_radix_node *squid_rn_addroute(void *, void *, struct squid_radix_node_head *, struct squid_radix_node[2]);

SQUIDCEXTERN struct squid_radix_node *squid_rn_delete(void *, void *, struct squid_radix_node_head *);

SQUIDCEXTERN struct squid_radix_node *squid_rn_insert(void *, struct squid_radix_node_head *, int *, struct squid_radix_node[2]);

SQUIDCEXTERN struct squid_radix_node *squid_rn_match(void *, struct squid_radix_node_head *);

SQUIDCEXTERN struct squid_radix_node *squid_rn_newpair(void *, int, struct squid_radix_node[2]);

SQUIDCEXTERN struct squid_radix_node *squid_rn_search(void *, struct squid_radix_node *);

SQUIDCEXTERN struct squid_radix_node *squid_rn_search_m(void *, struct squid_radix_node *, void *);

SQUIDCEXTERN struct squid_radix_node *squid_rn_lookup(void *, void *, struct squid_radix_node_head *);

#endif /* SQUID_RADIX_H */

