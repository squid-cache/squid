
typedef struct _splay_node {
	void *data;
	struct _splay_node *left;
	struct _splay_node *right;
} splayNode;

typedef int (*SPCMP) _PARAMS((const void *, splayNode *));

extern int splayLastResult;

splayNode *splay_insert _PARAMS((void *, splayNode *, SPCMP));
splayNode *splay_splay _PARAMS((const void *, splayNode *, SPCMP));
void splay_destroy _PARAMS((splayNode *, void (*) _PARAMS((void *))));

