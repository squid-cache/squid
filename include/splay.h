/*
 * $Id: splay.h,v 1.24 2003/09/02 22:57:00 robertc Exp $
 */

#ifndef SQUID_SPLAY_H
#define SQUID_SPLAY_H

#ifndef __cplusplus
/* legacy C bindings - can be removed when mempool is C++ */

typedef struct _splay_node
{
    void *data;

    struct _splay_node *left;

    struct _splay_node *right;
}

splayNode;

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

class SplayNode
{

public:
    typedef V Value;
    typedef int SPLAYCMP(Value const &a, Value const &b);
    typedef void SPLAYFREE(Value &);
    typedef void SPLAYWALKEE(Value const & nodedata, void *state);
    static void DefaultFree (Value &aValue) {delete aValue;}

    SplayNode<V> (Value const &);
    Value data;
    mutable SplayNode<V> *left;
    mutable SplayNode<V> *right;
    void destroy(SPLAYFREE *);
    void walk(SPLAYWALKEE *, void *callerState);
    SplayNode<V> const * start() const;
    SplayNode<V> const * end() const;

    SplayNode<V> * remove
        (const Value data, SPLAYCMP * compare);

    SplayNode<V> * insert(Value data, SPLAYCMP * compare);

    SplayNode<V> * splay(const Value &data, SPLAYCMP * compare) const;
};

typedef SplayNode<void *> splayNode;

template <class V>

class Splay
{

public:
    typedef V Value;
    typedef int SPLAYCMP(Value const &a, Value const &b);
    typedef void SPLAYFREE(Value &);
    Splay():head(NULL), elements (0){}

    mutable SplayNode<V> * head;
    Value const *find (Value const &, SPLAYCMP *compare) const;
    void insert(Value const &, SPLAYCMP *compare);

    void remove
        (Value const &, SPLAYCMP *compare);

    void destroy(SPLAYFREE *);

    SplayNode<V> const * start() const;

    SplayNode<V> const * end() const;

    size_t size() const;

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
SplayNode<V>::SplayNode (Value const &someData) : data(someData), left(NULL), right (NULL) {}

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
SplayNode<V> const *
SplayNode<V>::start() const
{
    if (this && left)
        return left->start();

    return this;
}

template<class V>
SplayNode<V> const *
SplayNode<V>::end() const
{
    if (this && right)
        return right->end();

    return this;
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
SplayNode<V>::remove
    (Value const dataToRemove, SPLAYCMP * compare)
{
    if (this == NULL)
        return NULL;

    SplayNode<V> *result = splay(dataToRemove, compare);

    if (splayLastResult == 0) {	/* found it */
        SplayNode<V> *newTop;

        if (result->left == NULL) {
            newTop = result->right;
        } else {
            newTop = result->left->splay(dataToRemove, compare);
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
SplayNode<V>::insert(Value dataToInsert, SPLAYCMP * compare)
{
    /* create node to insert */
    SplayNode<V> *newNode = new SplayNode<V>(dataToInsert);

    if (this == NULL) {
        splayLastResult = -1;
        newNode->left = newNode->right = NULL;
        return newNode;
    }

    SplayNode<V> *newTop = splay(dataToInsert, compare);

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
SplayNode<V>::splay(Value const &dataToFind, SPLAYCMP * compare) const
{
    if (this == NULL) {
        /* can't have compared successfully :} */
        splayLastResult = -1;
        return NULL;
    }

    SplayNode<V> N(dataToFind);
    SplayNode<V> *l;
    SplayNode<V> *r;
    SplayNode<V> *y;
    N.left = N.right = NULL;
    l = r = &N;

    SplayNode<V> *top = const_cast<SplayNode<V> *>(this);

    for (;;) {
        splayLastResult = compare(dataToFind, top->data);

        if (splayLastResult < 0) {
            if (top->left == NULL)
                break;

            if ((splayLastResult = compare(dataToFind, top->left->data)) < 0) {
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

            if ((splayLastResult = compare(dataToFind, top->right->data)) > 0) {
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
Splay<V>::remove
    (Value const &value, SPLAYCMP *compare)
{
    assert (find (value, compare));

    head = head->remove
           (value, compare);

    --elements;
}

template <class V>
SplayNode<V> const *
Splay<V>:: start() const
{
    if (head)
        return head->start();

    return NULL;
}

template <class V>
SplayNode<V> const *
Splay<V>:: end() const
{
    if (head)
        return head->end();

    return NULL;
}

template <class V>
void
Splay<V>:: destroy(SPLAYFREE *free_func)
{
    if (head)
        head->destroy(free_func);

    head = NULL;

    elements = 0;
}

template <class V>
size_t
Splay<V>::size() const
{
    return elements;
}

#endif

#endif /* SQUID_SPLAY_H */
