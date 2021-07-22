/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SPLAY_H
#define SQUID_SPLAY_H

#include "fatal.h"
#include <stack>

// private class of Splay. Do not use directly
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
    void destroy(SPLAYFREE * = DefaultFree);
    void walk(SPLAYWALKEE *, void *callerState);
    SplayNode<V> const * start() const;
    SplayNode<V> const * finish() const;

    SplayNode<V> * remove(const Value data, SPLAYCMP * compare);

    SplayNode<V> * insert(Value data, SPLAYCMP * compare);

    /// look in the splay for data for where compare(data,candidate) == true.
    /// return NULL if not found, a pointer to the sought data if found.
    template <class FindValue> SplayNode<V> * splay(const FindValue &data, int( * compare)(FindValue const &a, Value const &b)) const;

    /// recursively visit left nodes, this node, and then right nodes
    template <class Visitor> void visit(Visitor &v) const;
};

typedef SplayNode<void *> splayNode;

template <class V>
class SplayConstIterator;

template <class V>
class SplayIterator;

template <class V>
class Splay
{
public:
    typedef V Value;
    typedef int SPLAYCMP(Value const &a, Value const &b);
    typedef void SPLAYFREE(Value &);
    typedef SplayIterator<V> iterator;
    typedef const SplayConstIterator<V> const_iterator;
    Splay():head(NULL), elements (0) {}

    template <class FindValue> Value const *find (FindValue const &, int( * compare)(FindValue const &a, Value const &b)) const;

    void insert(Value const &, SPLAYCMP *compare);

    void remove(Value const &, SPLAYCMP *compare);

    void destroy(SPLAYFREE * = SplayNode<V>::DefaultFree);

    SplayNode<V> const * start() const;

    SplayNode<V> const * finish() const;

    size_t size() const;

    bool empty() const { return size() == 0; }

    const_iterator begin() const;

    const_iterator end() const;

    /// recursively visit all nodes, in left-to-right order
    template <class Visitor> void visit(Visitor &v) const;

private:
    mutable SplayNode<V> * head;
    size_t elements;
};

SQUIDCEXTERN int splayLastResult;

template<class V>
SplayNode<V>::SplayNode (Value const &someData) : data(someData), left(NULL), right (NULL) {}

template<class V>
void
SplayNode<V>::walk(SPLAYWALKEE * walkee, void *state)
{
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
    if (left)
        return left->start();

    return this;
}

template<class V>
SplayNode<V> const *
SplayNode<V>::finish() const
{
    if (right)
        return right->finish();

    return this;
}

template<class V>
void
SplayNode<V>::destroy(SPLAYFREE * free_func)
{
    if (left)
        left->destroy(free_func);

    if (right)
        right->destroy(free_func);

    free_func(data);

    delete this;
}

template<class V>
SplayNode<V> *
SplayNode<V>::remove(Value const dataToRemove, SPLAYCMP * compare)
{
    SplayNode<V> *result = splay(dataToRemove, compare);

    if (splayLastResult == 0) { /* found it */
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

    return result;          /* It wasn't there */
}

template<class V>
SplayNode<V> *
SplayNode<V>::insert(Value dataToInsert, SPLAYCMP * compare)
{
    /* create node to insert */
    SplayNode<V> *newNode = new SplayNode<V>(dataToInsert);
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
template<class FindValue>
SplayNode<V> *
SplayNode<V>::splay(FindValue const &dataToFind, int( * compare)(FindValue const &a, Value const &b)) const
{
    Value temp = Value();
    SplayNode<V> N(temp);
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
                y = top->left;  /* rotate right */
                top->left = y->right;
                y->right = top;
                top = y;

                if (top->left == NULL)
                    break;
            }

            r->left = top;  /* link right */
            r = top;
            top = top->left;
        } else if (splayLastResult > 0) {
            if (top->right == NULL)
                break;

            if ((splayLastResult = compare(dataToFind, top->right->data)) > 0) {
                y = top->right; /* rotate left */
                top->right = y->left;
                y->left = top;
                top = y;

                if (top->right == NULL)
                    break;
            }

            l->right = top; /* link left */
            l = top;
            top = top->right;
        } else {
            break;
        }
    }

    l->right = top->left;   /* assemble */
    r->left = top->right;
    top->left = N.right;
    top->right = N.left;
    return top;
}

template <class V>
template <class Visitor>
void
SplayNode<V>::visit(Visitor &visitor) const
{
    if (left)
        left->visit(visitor);
    visitor(data);
    if (right)
        right->visit(visitor);
}

template <class V>
template <class Visitor>
void
Splay<V>::visit(Visitor &visitor) const
{
    if (head)
        head->visit(visitor);
}

template <class V>
template <class FindValue>
typename Splay<V>::Value const *
Splay<V>::find (FindValue const &value, int( * compare)(FindValue const &a, Value const &b)) const
{
    if (head == NULL)
        return NULL;

    head = head->splay(value, compare);

    if (splayLastResult != 0)
        return NULL;

    return &head->data;
}

template <class V>
void
Splay<V>::insert(Value const &value, SPLAYCMP *compare)
{
    if (find(value, compare) != NULL) // ignore duplicates
        return;

    if (head == NULL)
        head = new SplayNode<V>(value);
    else
        head = head->insert(value, compare);
    ++elements;
}

template <class V>
void
Splay<V>::remove(Value const &value, SPLAYCMP *compare)
{
    // also catches the head==NULL case
    if (find(value, compare) == NULL)
        return;

    head = head->remove(value, compare);

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
Splay<V>:: finish() const
{
    if (head)
        return head->finish();

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

template <class V>
const SplayConstIterator<V>
Splay<V>::begin() const
{
    return const_iterator(head);
}

template <class V>
const SplayConstIterator<V>
Splay<V>::end() const
{
    return const_iterator(NULL);
}

// XXX: This does not seem to iterate the whole thing in some cases.
template <class V>
class SplayConstIterator
{

public:
    typedef const V value_type;
    SplayConstIterator (SplayNode<V> *aNode);
    bool operator == (SplayConstIterator const &right) const;
    SplayConstIterator operator ++ (int dummy);
    SplayConstIterator &operator ++ ();
    V const & operator * () const;

private:
    void advance();
    void addLeftPath(SplayNode<V> *aNode);
    void init(SplayNode<V> *);
    std::stack<SplayNode<V> *> toVisit;
};

template <class V>
SplayConstIterator<V>::SplayConstIterator (SplayNode<V> *aNode)
{
    init(aNode);
}

template <class V>
bool
SplayConstIterator<V>::operator == (SplayConstIterator const &right) const
{
    if (toVisit.empty() && right.toVisit.empty())
        return true;
    if (!toVisit.empty() && !right.toVisit.empty())
        return toVisit.top() == right.toVisit.top();
    // only one of the two is empty
    return false;
}

template <class V>
SplayConstIterator<V> &
SplayConstIterator<V>::operator ++ ()
{
    advance();
    return *this;
}

template <class V>
SplayConstIterator<V>
SplayConstIterator<V>::operator ++ (int dummy)
{
    SplayConstIterator<V> result = *this;
    advance();
    return result;
}

/* advance is simple enough:
* if the stack is empty, we're done.
* otherwise, pop the last visited node
* then, pop the next node to visit
* if that has a right child, add it and it's
* left-to-end path.
* then add the node back.
*/
template <class V>
void
SplayConstIterator<V>::advance()
{
    if (toVisit.empty())
        return;

    toVisit.pop();

    if (toVisit.empty())
        return;

    // not empty
    SplayNode<V> *currentNode = toVisit.top();
    toVisit.pop();

    addLeftPath(currentNode->right);

    toVisit.push(currentNode);
}

template <class V>
void
SplayConstIterator<V>::addLeftPath(SplayNode<V> *aNode)
{
    if (aNode == NULL)
        return;

    do {
        toVisit.push(aNode);
        aNode = aNode->left;
    } while (aNode != NULL);
}

template <class V>
void
SplayConstIterator<V>::init(SplayNode<V> *head)
{
    addLeftPath(head);
}

template <class V>
V const &
SplayConstIterator<V>::operator * () const
{
    /* can't dereference when past the end */

    if (toVisit.size() == 0)
        fatal ("Attempt to dereference SplayConstIterator past-the-end\n");

    return toVisit.top()->data;
}

#endif /* SQUID_SPLAY_H */

