/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_INCLUDE_SPLAY_H
#define SQUID_INCLUDE_SPLAY_H

#include "fatal.h"
#include <cstddef>
#include <stack>

// private class of Splay. Do not use directly
template <class V>
class SplayNode
{
public:
    typedef V Value;
    typedef int SPLAYCMP(Value const &a, Value const &b);

    SplayNode<V> (Value const &);
    Value data;
    mutable SplayNode<V> *left;
    mutable SplayNode<V> *right;
    mutable SplayNode<V> *visitThreadUp;

    SplayNode<V> const * start() const;
    SplayNode<V> const * finish() const;

    SplayNode<V> * remove(const Value data, SPLAYCMP * compare);

    SplayNode<V> * insert(Value data, SPLAYCMP * compare);

    /// look in the splay for data for where compare(data,candidate) == true.
    /// return NULL if not found, a pointer to the sought data if found.
    template <class FindValue> SplayNode<V> * splay(const FindValue &data, int( * compare)(FindValue const &a, Value const &b)) const;
};

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

    static void DefaultFree(Value &v) { delete v; }

    Splay():head(nullptr), elements (0) {}

    template <class FindValue> Value const *find (FindValue const &, int( * compare)(FindValue const &a, Value const &b)) const;

    /// If the given value matches a stored one, returns that matching value.
    /// Otherwise, stores the given unique value and returns nil.
    const Value *insert(const Value &, SPLAYCMP *);

    void remove(Value const &, SPLAYCMP *compare);

    void destroy(SPLAYFREE * = DefaultFree);

    SplayNode<V> const * start() const;

    SplayNode<V> const * finish() const;

    size_t size() const;

    bool empty() const { return size() == 0; }

    const_iterator begin() const;

    const_iterator end() const;

    /// left-to-right visit of all stored Values
    template <typename ValueVisitor> void visit(ValueVisitor &) const;

private:
    /// left-to-right walk through all nodes
    template <typename NodeVisitor> void visitEach(NodeVisitor &) const;

    mutable SplayNode<V> * head;
    size_t elements;
};

SQUIDCEXTERN int splayLastResult;

template<class V>
SplayNode<V>::SplayNode(const Value &someData): data(someData), left(nullptr), right(nullptr), visitThreadUp(nullptr) {}

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
Splay<V>::visitEach(Visitor &visitor) const
{
    // In-order walk through tree using modified Morris Traversal: To avoid a
    // leftover thread up (and, therefore, a fatal loop in the tree) due to a
    // visitor exception, we use an extra pointer visitThreadUp instead of
    // manipulating the right child link and interfering with other methods
    // that use that link.
    // This also helps to distinguish between up and down movements, eliminating
    // the need to descent into left subtree a second time after traversing the
    // thread to find the loop and remove the temporary thread.

    if (!head)
        return;

    auto cur = head;
    auto movedUp = false;
    cur->visitThreadUp = nullptr;

    while (cur) {
        if (!cur->left || movedUp) {
            // no (unvisited) left subtree, so handle current node ...
            const auto old = cur;
            if (cur->right) {
                // ... and descent into right subtree
                cur = cur->right;
                movedUp = false;
            }
            else if (cur->visitThreadUp) {
                // ... or back up the thread
                cur = cur->visitThreadUp;
                movedUp = true;
            } else {
                // end of traversal
                cur = nullptr;
            }
            visitor(old);
            // old may be destroyed here
        } else {
            // first descent into left subtree

            // find right-most child in left tree
            auto rmc = cur->left;
            while (rmc->right) {
                rmc->visitThreadUp = nullptr; // cleanup old threads on the way
                rmc = rmc->right;
            }
            // create thread up back to cur
            rmc->visitThreadUp = cur;

            // finally descent into left subtree
            cur = cur->left;
            movedUp = false;
        }
    }
}

template <class V>
template <class Visitor>
void
Splay<V>::visit(Visitor &visitor) const
{
    const auto internalVisitor = [&visitor](const SplayNode<V> *node) { visitor(node->data); };
    visitEach(internalVisitor);
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
typename Splay<V>::Value const *
Splay<V>::insert(Value const &value, SPLAYCMP *compare)
{
    if (const auto similarValue = find(value, compare))
        return similarValue; // do not insert duplicates

    if (head == nullptr)
        head = new SplayNode<V>(value);
    else
        head = head->insert(value, compare);
    ++elements;

    return nullptr; // no duplicates found
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
    const auto destroyer = [free_func](SplayNode<V> *node) { free_func(node->data); delete node; };
    visitEach(destroyer);

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

#endif /* SQUID_INCLUDE_SPLAY_H */

