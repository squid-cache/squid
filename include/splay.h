/*
 * $Id: splay.h,v 1.14 2003/02/05 10:36:31 robertc Exp $
 */

#ifndef SQUID_SPLAY_H
#define SQUID_SPLAY_H

#ifndef __cplusplus
/* legacy C bindings - can be removed when mempool is C++ */
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
#else

template <class V>
class SplayNode {
  public:
    typedef V Value;
    Value *data;
    SplayNode<V> *left;
    SplayNode<V> *right;
};

typedef SplayNode<void> splayNode;

typedef int SPLAYCMP(const void *a, const void *b);
typedef void SPLAYWALKEE(void *nodedata, void *state);
typedef void SPLAYFREE(void *);

SQUIDCEXTERN int splayLastResult;

SQUIDCEXTERN splayNode *splay_insert(void *, splayNode *, SPLAYCMP *);
SQUIDCEXTERN splayNode *splay_splay(const void *, splayNode *, SPLAYCMP *);
SQUIDCEXTERN splayNode *splay_delete(const void *, splayNode *, SPLAYCMP *);
SQUIDCEXTERN void splay_destroy(splayNode *, SPLAYFREE *);
SQUIDCEXTERN void splay_walk(splayNode *, SPLAYWALKEE *, void *);


#endif

#endif /* SQUID_SPLAY_H */
