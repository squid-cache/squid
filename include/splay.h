/*
 * $Id: splay.h,v 1.7 1998/09/23 17:20:05 wessels Exp $
 */


typedef struct _splay_node {
    void *data;
    struct _splay_node *left;
    struct _splay_node *right;
} splayNode;

typedef int SPLAYCMP(const void *, splayNode *);
typedef void SPLAYWALKEE(void *, void *);
typedef void SPLAYFREE(void *);

extern int splayLastResult;

extern splayNode *splay_insert(void *, splayNode *, SPLAYCMP *);
extern splayNode *splay_splay(const void *, splayNode *, SPLAYCMP *);
extern void splay_destroy(splayNode *, SPLAYFREE *);
extern void splay_walk(splayNode *, SPLAYWALKEE *, void *);
