
typedef struct _splay_node {
    void *data;
    struct _splay_node *left;
    struct _splay_node *right;
} splayNode;

typedef int SPCMP(const void *, splayNode *);

extern int splayLastResult;

splayNode *splay_insert(void *, splayNode *, SPCMP *);
splayNode *splay_splay(const void *, splayNode *, SPCMP *);
void splay_destroy(splayNode *, void (*)(void *));
