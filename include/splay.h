/*
 * $Id: splay.h,v 1.12 2002/10/13 20:34:51 robertc Exp $
 */

#ifndef SQUID_SPLAY_H
#define SQUID_SPLAY_H

typedef struct _splay_node {
    void *data;
    struct _splay_node *left;
    struct _splay_node *right;
} splayNode;

typedef int SPLAYCMP(const void *a, const void *b);
typedef void SPLAYWALKEE(void *nodedata, void *state);
typedef void SPLAYFREE(void *);

SQUIDCEXTERN int splayLastResult;

SQUIDCEXTERN splayNode *splay_insert(void *, splayNode *, SPLAYCMP *);
SQUIDCEXTERN splayNode *splay_splay(const void *, splayNode *, SPLAYCMP *);
SQUIDCEXTERN splayNode *splay_delete(const void *, splayNode *, SPLAYCMP *);
SQUIDCEXTERN void splay_destroy(splayNode *, SPLAYFREE *);
SQUIDCEXTERN void splay_walk(splayNode *, SPLAYWALKEE *, void *);

#endif /* SQUID_SPLAY_H */
