/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

    /// left-to-right visit of all nodes using Morris Traversal
    template <class Visitor> void visit(Visitor &v) const;
private:
    mutable SplayNode<V> *visit_thread_up;

    struct SplayNodeWalkeeVisitor {
        SPLAYWALKEE* walkee;
        void *       state;
        explicit SplayNodeWalkeeVisitor(SPLAYWALKEE* w, void *s): walkee{w}, state{s} {}
        void operator() (Value const &data) {
            walkee(data, state);
        }
    };

};

typedef SplayNode<void *> splayNode;

template <class V>
class SplayConstIterator;

template <class V>
class Splay
{
public:
    typedef V Value;
    typedef int SPLAYCMP(Value const &a, Value const &b);
    typedef void SPLAYFREE(Value &);
    typedef const SplayConstIterator<V> const_iterator;
    Splay():head(nullptr), elements (0) {}

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

    /// left-to-right visit of all nodes
    template <class Visitor> void visit(Visitor &v) const;

private:
    mutable SplayNode<V> * head;
    size_t elements;
};

SQUIDCEXTERN int splayLastResult;

template<class V>
SplayNode<V>::SplayNode (Value const &someData) : data(someData), left(nullptr), right (nullptr) {}


template<class V>
void
SplayNode<V>::walk(SPLAYWALKEE * walkee, void *state)
{
    SplayNodeWalkeeVisitor visitor(walkee, state);
    visit(visitor);
}

template<class V>
SplayNode<V> const *
SplayNode<V>::start() const
{
    auto cur = this;
    while (cur->left)
        cur = cur->left;

    return cur;
}

template<class V>
SplayNode<V> const *
SplayNode<V>::finish() const
{
    auto cur = this;
    while (cur->right)
        cur = cur->right;

    return cur;
}

template<class V>
void
SplayNode<V>::destroy(SPLAYFREE * free_func)
{
    // Use a modified Morris Traversal because a destroy function
    // based on a visit()-like traversal with a visitor would have to
    // call delete on the root SplayNode-object (this) in-order, not last.
    //
    // Start with the top node as current node C.
    //
    // Repeat, until no more child nodes exist:
    // a) If C has no left child, set C to the C->right
    //    and delete the previous node C.
    // b) If C has a left child C->left, find the right-most node RMN in the
    //    left subtree of C.
    //    - RMN can't have a right child!
    //    - Instead of linking RMN->right to C as a way back up like in Morris
    //      Traversal, we MOVE C->right to RMN->right.
    //    - As C now has only a single child (C->left),
    //      move C to C->left an delete the previous node C.
    //
    // Because we move the right subtree down into the left subtree and remove
    // the parent from the tree, there is - in contrast to the Morris
    // Traversal - no way up and no need to check for this loop case.
    // We only need to avoid deleting the original top node (this) until all
    // other nodes are deleted.
    //
    // There is no need for additional data structures, so storage need is O(1).
    // As every node is at most visited once for RMN search and once for deletion,
    // cpu need is O(n).

    auto cur = this;
    while (cur != nullptr) {
        if (cur->left == nullptr) {
            // no left tree -> descent into right subtree and delete old top
            auto top = cur;
            cur = cur->right;
            free_func(top->data);
            top->right = nullptr;
            if (top != this)
                delete top;
        } else {
            if (cur->right) {
                // find right-most child in left tree
                // to store a link to right subtree
                auto rmc = cur->left;
                while (rmc->right)
                    rmc = rmc->right;

                // move right subtree into left subtree
                rmc->right = cur->right;
                cur->right = nullptr;
            }

            // descent into left subtree and delete old top
            auto top = cur;
            cur = cur->left;
            free_func(top->data);
            top->left = nullptr;
            if (top != this)
                delete top;
        }
    }

    // finally delete this node
    delete this;
}

template<class V>
SplayNode<V> *
SplayNode<V>::remove(Value const dataToRemove, SPLAYCMP * compare)
{
    SplayNode<V> *result = splay(dataToRemove, compare);

    if (splayLastResult == 0) { /* found it */
        SplayNode<V> *newTop;

        if (result->left == nullptr) {
            newTop = result->right;
        } else {
            newTop = result->left->splay(dataToRemove, compare);
            /* temporary */
            newTop->right = result->right;
            result->right = nullptr;
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
        newTop->left = nullptr;
        return newNode;
    } else if (splayLastResult > 0) {
        newNode->right = newTop->right;
        newNode->left = newTop;
        newTop->right = nullptr;
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
    N.left = N.right = nullptr;
    l = r = &N;

    SplayNode<V> *top = const_cast<SplayNode<V> *>(this);

    for (;;) {
        splayLastResult = compare(dataToFind, top->data);

        if (splayLastResult < 0) {
            if (top->left == nullptr)
                break;

            if ((splayLastResult = compare(dataToFind, top->left->data)) < 0) {
                y = top->left;  /* rotate right */
                top->left = y->right;
                y->right = top;
                top = y;

                if (top->left == nullptr)
                    break;
            }

            r->left = top;  /* link right */
            r = top;
            top = top->left;
        } else if (splayLastResult > 0) {
            if (top->right == nullptr)
                break;

            if ((splayLastResult = compare(dataToFind, top->right->data)) > 0) {
                y = top->right; /* rotate left */
                top->right = y->left;
                y->left = top;
                top = y;

                if (top->right == nullptr)
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
    // in-order walk through tree using modified Morris Traversal:
    // to avoid a left-over thread up due to an exception in
    // visit (and therefor a fatal loop in the tree), we use
    // an extra pointer visit_thread_up, that doesn't interfere
    // with other methods.
    // This also helps to distinguish between up and down movements
    // and therefor we do not need to descent into left subtree
    // a second time after traversing the thread to find the loop
    // cut the thread.
    SplayNode<V> *cur = const_cast<SplayNode<V> *>(this);
    bool moved_up = false;
    visit_thread_up = nullptr;

    while (cur != nullptr) {
        if (cur->left == nullptr or moved_up) {
            // no (unvisited) left subtree, so
            // handle current node ...
            visitor(cur->data);
            if (cur->right) {
                // ... and descent into right subtree
                cur = cur->right;
                moved_up = false;
            }
            else if (cur->visit_thread_up) {
                // .. or back up the thread
                cur = cur->visit_thread_up;
                moved_up = true;
            } else {
                // end of traversal
                cur = nullptr;
                break;
            }
        } else {
            // first descent into left subtree

            // find right-most child in left tree
            auto rmc = cur->left;
            while (rmc->right) {
                rmc->visit_thread_up = nullptr; // cleanup old threads on the way
                rmc = rmc->right;
            }
            // create thread up back to cur
            rmc->visit_thread_up = cur;

            // finally descent into left subtree
            cur = cur->left;
            moved_up = false;
        }
    }
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
    if (head == nullptr)
        return nullptr;

    head = head->splay(value, compare);

    if (splayLastResult != 0)
        return nullptr;

    return &head->data;
}

template <class V>
void
Splay<V>::insert(Value const &value, SPLAYCMP *compare)
{
    if (find(value, compare) != nullptr) // ignore duplicates
        return;

    if (head == nullptr)
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
    if (find(value, compare) == nullptr)
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

    return nullptr;
}

template <class V>
SplayNode<V> const *
Splay<V>:: finish() const
{
    if (head)
        return head->finish();

    return nullptr;
}

template <class V>
void
Splay<V>:: destroy(SPLAYFREE *free_func)
{
    if (head)
        head->destroy(free_func);

    head = nullptr;

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
    return const_iterator(nullptr);
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
SplayConstIterator<V>::operator ++ (int)
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
    if (aNode == nullptr)
        return;

    do {
        toVisit.push(aNode);
        aNode = aNode->left;
    } while (aNode != nullptr);
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

