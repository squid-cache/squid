/*
 * $Id: splay.h,v 1.18 2003/03/06 11:51:55 robertc Exp $
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

typedef int SPLAYCMP(const void **a, const void **b);
typedef void SPLAYWALKEE(void **nodedata, void *state);

SQUIDCEXTERN int splayLastResult;

/* MUST match C++ prototypes */
SQUIDCEXTERN splayNode *splay_insert(void *, splayNode *, SPLAYCMP *);
SQUIDCEXTERN splayNode *splay_splay(const void **, splayNode *, SPLAYCMP *);
SQUIDCEXTERN splayNode *splay_delete(const void *, splayNode *, SPLAYCMP *);
SQUIDCEXTERN void splay_walk(splayNode *, SPLAYWALKEE *, void *);
#else


template <class V>
class SplayNode {
  public:
    typedef V Value;
    typedef int SPLAYCMP(Value const &a, Value const &b);
    typedef void SPLAYFREE(Value &);
    typedef void SPLAYWALKEE(Value const & nodedata, void *state);
    static void DefaultFree (Value &aValue) {aValue->deleteSelf();}
    Value data;
    mutable SplayNode<V> *left;
    mutable SplayNode<V> *right;
    void destroy(SPLAYFREE *);
    void walk(SPLAYWALKEE *, void *callerState);
    SplayNode<V> * remove(const Value data, SPLAYCMP * compare);
    SplayNode<V> * insert(Value data, SPLAYCMP * compare);
    SplayNode<V> * splay(const Value &data, SPLAYCMP * compare) const;
};

typedef SplayNode<void *> splayNode;

template <class V>
class Splay {
  public:
    typedef V Value;
    typedef int SPLAYCMP(Value const &a, Value const &b);
    Splay():head(NULL), elements (0){}
    mutable SplayNode<V> * head;
    Value const *find (Value const &, SPLAYCMP *compare) const;
    void insert(Value const &, SPLAYCMP *compare);
    void remove(Value const &, SPLAYCMP *compare);
    size_t elements;
};


SQUIDCEXTERN int splayLastResult;

SQUIDCEXTERN splayNode *splay_insert(void *, splayNode *, splayNode::SPLAYCMP *);
SQUIDCEXTERN splayNode *splay_delete(const void *, splayNode *, splayNode::SPLAYCMP *);
SQUIDCEXTERN splayNode *splay_splay(const void **, splayNode *, splayNode::SPLAYCMP *);
SQUIDCEXTERN void splay_destroy(splayNode *, splayNode::SPLAYFREE *);
SQUIDCEXTERN void splay_walk(splayNode *, splayNode::SPLAYWALKEE *, void *callerState);

/* inline methods */
template<class V>
void
SplayNode<V>::walk(SPLAYWALKEE * walkee, void *state)
{
    if (this == NULL)
	return;
    if (left)
	left->walk(walkee, state);
    walkee(data, state);
    if (right)
	right->walk(walkee, state);
}

template<class V>
void
SplayNode<V>::destroy(SPLAYFREE * free_func)
{
    if (!this)
	return;
    if (left)
	left->destroy(free_func);
    if (right)
	right->destroy(free_func);
    free_func(data);
    delete this;
}

template<class V>
SplayNode<V> *
SplayNode<V>::remove(Value const data, SPLAYCMP * compare)
{
    if (this == NULL)
	return NULL;
    SplayNode<V> *result = splay(data, compare);
    if (splayLastResult == 0) {	/* found it */
	SplayNode<V> *newTop;
	if (result->left == NULL) {
	    newTop = result->right;
	} else {
	    newTop = result->left->splay(data, compare);
	    /* temporary */
	    newTop->right = result->right;
	    result->right = NULL;
	}
	delete result;
	return newTop;
    }
    return result;			/* It wasn't there */
}

template<class V>
SplayNode<V> *
SplayNode<V>::insert(Value data, SPLAYCMP * compare)
{
    /* create node to insert */
    SplayNode<V> *newNode = new SplayNode<V>;
    newNode->data = data;
    if (this == NULL) {
	splayLastResult = -1;
	newNode->left = newNode->right = NULL;
	return newNode;
    }
    
    SplayNode<V> *newTop = splay(data, compare);
    if (splayLastResult < 0) {
	newNode->left = newTop->left;
	newNode->right = newTop;
	newTop->left = NULL;
	return newNode;
    } else if (splayLastResult > 0) {
	newNode->right = newTop->right;
	newNode->left = newTop;
	newTop->right = NULL;
	return newNode;
    } else {
	/* duplicate entry */
	delete newNode;
	return newTop;
    }
}

template<class V>
SplayNode<V> *
SplayNode<V>::splay(Value const &data, SPLAYCMP * compare) const
{
    if (this == NULL) {
	/* can't have compared successfully :} */
	splayLastResult = -1;
	return NULL;
    }
    SplayNode<V> N;
    SplayNode<V> *l;
    SplayNode<V> *r;
    SplayNode<V> *y;
    N.left = N.right = NULL;
    l = r = &N;

    SplayNode<V> *top = const_cast<SplayNode<V> *>(this);
    for (;;) {
	splayLastResult = compare(data, top->data);
	if (splayLastResult < 0) {
	    if (top->left == NULL)
		break;
	    if ((splayLastResult = compare(data, top->left->data)) < 0) {
		y = top->left;	/* rotate right */
		top->left = y->right;
		y->right = top;
		top = y;
		if (top->left == NULL)
		    break;
	    }
	    r->left = top;	/* link right */
	    r = top;
	    top = top->left;
	} else if (splayLastResult > 0) {
	    if (top->right == NULL)
		break;
	    if ((splayLastResult = compare(data, top->right->data)) > 0) {
		y = top->right;	/* rotate left */
		top->right = y->left;
		y->left = top;
		top = y;
		if (top->right == NULL)
		    break;
	    }
	    l->right = top;	/* link left */
	    l = top;
	    top = top->right;
	} else {
	    break;
	}
    }
    l->right = top->left;	/* assemble */
    r->left = top->right;
    top->left = N.right;
    top->right = N.left;
    return top;
}

template <class V>
typename Splay<V>::Value const *
Splay<V>::find (Value const &value, SPLAYCMP *compare) const
{
    head = head->splay(value, compare);
    if (splayLastResult != 0)
	return NULL;
    return &head->data;
}

template <class V>
void
Splay<V>::insert(Value const &value, SPLAYCMP *compare)
{
    assert (!find (value, compare));
    head = head->insert(value, compare);
    ++elements;
}

template <class V>
void
Splay<V>::remove(Value const &value, SPLAYCMP *compare)
{
    assert (find (value, compare));
    head = head->remove(value, compare);
    --elements;
}

#endif

#endif /* SQUID_SPLAY_H */
