/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * AUTHOR: John Dilley, Hewlett Packard
 */

/****************************************************************************
 * Heap implementation
 * Copyright (C) 1999 by Hewlett Packard
 ****************************************************************************/

#include "squid.h"
#include "heap.h"

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

#include "util.h"

/*
 * Hacks for non-synchronized heap implementation.
 */
#define         mutex_lock(m)           (void)0
#define         mutex_unlock(m)         (void)0
#define         mutex_trylock(m)        (void)0
#define         mutex_init(m)           ((m)=123456)

/*
 * Private function prototypes.
 */
static void _heap_ify_up(heap * hp, heap_node * elm);
static void _heap_ify_down(heap * hp, heap_node * elm);
static int _heap_should_grow(heap * hp);
static void _heap_grow(heap * hp);
static void _heap_swap_element(heap * hp, heap_node * elm1, heap_node * elm2);
static int _heap_node_exist(heap * hp, int id);

#ifdef  HEAP_DEBUG
void _heap_print_tree(heap * hp, heap_node * node);
#endif /* HEAP_DEBUG */

#define Left(x) (2 * (x) + 1)
#define Right(x) (2 * (x) + 2)
#define Parent(x) ((int)((x)-1)/2)

#define Threshold 10000
#define NormalRate 2
#define SlowRate 1.5
#define MinSize 32

/****************************************************************************
 * Public functions
 ****************************************************************************/

/*
 * Return a newly created heap. INITSIZE is the initial size of the heap.
 */
heap *
new_heap(int initSize, heap_key_func gen_key)
{
    heap *hp = xmalloc(sizeof(*hp));
    assert(hp != NULL);

    if (initSize <= 0)
        initSize = MinSize;
    hp->nodes = xcalloc(initSize, sizeof(heap_node *));
    assert(hp->nodes != NULL);

    hp->size = initSize;
    hp->last = 0;
    hp->gen_key = gen_key;
    hp->age = 0;

    return hp;
}

/*
 * Free memory used by a heap.  Does not free the metadata pointed to by the
 * heap nodes, only the heap's internal memory.
 */
void
delete_heap(heap * hp)
{
    int i;
    assert(hp != NULL);
    for (i = 0; i < hp->last; i++) {
        xfree(hp->nodes[i]);
    }
    xfree(hp->nodes);
    xfree(hp);
}

/*
 * Insert DAT based on KY into HP maintaining the heap property.
 * Return the newly inserted heap node. The fields of ELM other
 * than ID are never changed until ELM is deleted from HP, i.e.
 * caller can assume that the heap node always exist at the same
 * place in memory unless heap_delete or heap_extractmin is called
 * on that node.  This function exposes the heap's internal data
 * structure to the caller.  This is required in order to do O(lgN)
 * deletion.
 */
heap_node *
heap_insert(heap * hp, void *dat)
{
    heap_node *elm = xmalloc(sizeof(*elm));

    elm->key = heap_gen_key(hp, dat);
    elm->data = dat;

    if (_heap_should_grow(hp))
        _heap_grow(hp);

    hp->nodes[hp->last] = elm;
    elm->id = hp->last;
    hp->last += 1;

    _heap_ify_up(hp, elm);

    return elm;
}

/*
 * Delete ELM while maintaining the heap property. ELM may be modified.
 * Assumes that ELM is not NULL and frees it.  Returns the data pointed to
 * in, which the caller must free if necessary.
 */
heap_t
heap_delete(heap * hp, heap_node * elm)
{
    heap_node *lastNode;
    heap_t data = elm->data;

    assert(_heap_node_exist(hp, hp->last - 1));

    lastNode = hp->nodes[hp->last - 1];
    _heap_swap_element(hp, lastNode, elm);
    heap_extractlast(hp);

    if (elm == lastNode) {
        /*
         * lastNode just got freed, so don't access it in the next
         * block.
         */
        (void) 0;
    } else if (hp->last > 0) {
        if (lastNode->key < hp->nodes[Parent(lastNode->id)]->key)
            _heap_ify_up(hp, lastNode);     /* COOL! */
        _heap_ify_down(hp, lastNode);
    }
    return data;
}

/*
 * Delete the last element (leaf) out of the heap.  Does not require a
 * heapify operation.
 */

#ifndef heap_gen_key
/*
 * Function to generate keys.  See macro definition in heap.h.
 */
heap_key
heap_gen_key(heap * hp, heap_t dat)
{
    return hp->gen_key(dat, hp->age);
}
#endif /* heap_gen_key */

/*
 * Returns the data of the node with the largest KEY value and removes that
 * node from the heap.  Returns NULL if the heap was empty.
 */
heap_t
heap_extractmin(heap * hp)
{
    heap_t data;

    if (hp->last <= 0)
        return NULL;

    mutex_lock(hp->lock);

    data = hp->nodes[0]->data;
    heap_delete(hp, hp->nodes[0]);  /* Delete the root */

    mutex_unlock(hp->lock);

    return data;
}

/*
 * Remove the last node in HP.  Frees the heap internal structure and
 * returns the data pointes to by the last node.
 */
heap_t
heap_extractlast(heap * hp)
{
    heap_t data;
    assert(_heap_node_exist(hp, hp->last - 1));
    hp->last -= 1;
    data = hp->nodes[hp->last]->data;
    xfree(hp->nodes[hp->last]);
    return data;
}

/*
 * The semantics of this routine is the same as the followings:
 *        heap_delete(hp, elm);
 *        heap_insert(hp, dat);
 * Returns the old data object from elm (the one being replaced).  The
 * caller must free this as necessary.
 */
heap_t
heap_update(heap * hp, heap_node * elm, void *dat)
{
    heap_t old = elm->data;
    heap_key ky = heap_gen_key(hp, dat);

    elm->key = ky;
    elm->data = dat;

    if (elm->key < hp->nodes[Parent(elm->id)]->key)
        _heap_ify_up(hp, elm);
    _heap_ify_down(hp, elm);

    return old;
}

/*
 * A pointer to the root node's DATA.
 */
void *
heap_peepmin(heap * hp)
{
    assert(_heap_node_exist(hp, 0));
    return hp->nodes[0]->data;
}

/*
 * The KEY of the root node.
 */
heap_key
heap_peepminkey(heap * hp)
{
    assert(_heap_node_exist(hp, 0));
    return hp->nodes[0]->key;
}

/*
 * Same as heap_peep except that this return the KEY of the node.
 * Only meant for iteration.
 */
heap_key
heap_peepkey(heap * hp, int n)
{
    assert(_heap_node_exist(hp, n));
    return hp->nodes[n]->key;
}

/*
 * A pointer to Nth node's DATA. The caller can iterate through HP by
 * calling this routine.  eg. Caller can execute the following code:
 *   for(i = 0; i < heap_nodes(hp); i++)
 *      data = heap_peep(hp, i);
 */
void *
heap_peep(heap * hp, int n)
{
    void *data;
    assert(_heap_node_exist(hp, n));
    data = hp->nodes[n]->data;
    return data;
}

#ifndef heap_nodes
/*
 * Current number of nodes in HP.
 */
int
heap_nodes(heap * hp)
{
    return hp->last;
}
#endif /* heap_nodes */

#ifndef heap_empty
/*
 * Determine if the heap is empty.  Returns 1 if HP has no elements and 0
 * otherwise.
 */
int
heap_empty(heap * hp)
{
    return (hp->last <= 0) ? 1 : 0;
}
#endif /* heap_empty */

/****************** Private Functions *******************/

/*
 * Maintain the heap order property (parent is smaller than children) which
 * may only be violated at ELM downwards.  Assumes caller has locked the heap.
 */
static void
_heap_ify_down(heap * hp, heap_node * elm)
{
    heap_node *kid;
    int left = 0, right = 0;
    int isTrue = 1;
    while (isTrue) {
        left = Left(elm->id);
        right = Right(elm->id);
        if (!_heap_node_exist(hp, left)) {
            /* At the bottom of the heap (no child). */

            assert(!_heap_node_exist(hp, right));
            break;
        } else if (!_heap_node_exist(hp, right))
            /*  Only left child exists. */

            kid = hp->nodes[left];
        else {
            if (hp->nodes[right]->key < hp->nodes[left]->key)
                kid = hp->nodes[right];
            else
                kid = hp->nodes[left];
        }
        if (elm->key <= kid->key)
            break;
        _heap_swap_element(hp, kid, elm);
    }
}

/*
 * Maintain the heap property above ELM.  Caller has locked the heap.
 */
static void
_heap_ify_up(heap * hp, heap_node * elm)
{
    heap_node *parentNode;
    while (elm->id > 0) {
        parentNode = hp->nodes[Parent(elm->id)];
        if (parentNode->key <= elm->key)
            break;
        _heap_swap_element(hp, parentNode, elm);    /* Demote the parent. */
    }
}

/*
 * Swap the position of ELM1 and ELM2 in heap structure. Their IDs are also
 * swapped.
 */
static void
_heap_swap_element(heap * hp, heap_node * elm1, heap_node * elm2)
{
    int elm1Id = elm1->id;
    elm1->id = elm2->id;
    elm2->id = elm1Id;
    hp->nodes[elm1->id] = elm1;
    hp->nodes[elm2->id] = elm2;
}

#ifdef  NOTDEF
/*
 * Copy KEY and DATA fields of SRC to DEST. ID field is NOT copied.
 */
static void
_heap_copy_element(heap_node * src, heap_node * dest)
{
    dest->key = src->key;
    dest->data = src->data;
}

#endif /* NOTDEF */

/*
 * True if HP needs to be grown in size.
 */
static int
_heap_should_grow(heap * hp)
{
    if (hp->size <= hp->last)
        return 1;
    return 0;
}

/*
 * Grow HP.
 */
static void
_heap_grow(heap * hp)
{
    int newSize;

    if (hp->size > Threshold)
        newSize = hp->size * SlowRate;
    else
        newSize = hp->size * NormalRate;

    hp->nodes = xrealloc(hp->nodes, newSize * sizeof(heap_node *));
#if COMMENTED_OUT
    for (i = 0; i < hp->size; i++)
        newNodes[i] = hp->nodes[i];
    xfree(hp->nodes);
    hp->nodes = newNodes;
#endif
    hp->size = newSize;
}

/*
 * True if a node with ID exists in HP.
 */
static int
_heap_node_exist(heap * hp, int id)
{
    if ((id >= hp->last) || (id < 0) || (hp->nodes[id] == NULL))
        return 0;
    return 1;
}

/****************************************************************************
 * Printing and debug functions
 ****************************************************************************/

/*
 * Print the heap in element order, id..last.
 */
static void
heap_print_inorder(heap * hp, int id)
{
    while (id < hp->last) {
        printf("%d\tKey = %.04f\n", id, hp->nodes[id]->key);
        id++;
    }
}

/*
 * Returns 1 if HP maintians the heap property and 0 otherwise.
 */
int
verify_heap_property(heap * hp)
{
    int i = 0;
    int correct = 1;
    for (i = 0; i < hp->last / 2; i++) {
        correct = 1;
        if (_heap_node_exist(hp, Left(i)))
            if (hp->nodes[i]->key > hp->nodes[Left(i)]->key)
                correct = 0;
        if (_heap_node_exist(hp, Right(i)))
            if (hp->nodes[i]->key > hp->nodes[Right(i)]->key)
                correct = 0;
        if (!correct) {
            printf("verifyHeap: violated at %d", i);
            heap_print_inorder(hp, 0);
            break;
        }
    }
    return correct;
}

#ifdef  MEASURE_HEAP_SKEW

/****************************************************************************
 * Heap skew computation
 ****************************************************************************/

int
compare_heap_keys(const void *a, const void *b)
{
    heap_node **an = (heap_node **) a;
    heap_node **bn = (heap_node **) b;
    float cmp = (*an)->key - (*bn)->key;
    if (cmp < 0)
        return -1;
    else
        return 1;
}

/*
 * Compute the heap skew for HEAP, a measure of how out-of-order the
 * elements in the heap are.  The skew of a heap node is the difference
 * between its current position in the heap and where it would be if the
 * heap were in sorted order.  To compute this we have to sort the heap.  At
 * the end if the flag REPLACE is non-zero the heap will be returned in
 * sorted order (with skew == 0).  Note: using REPLACE does not help the
 * performance of the heap, so only do this if you really want to have a
 * sorted heap.  It is faster not to replace.
 */
float
calc_heap_skew(heap * heap, int replace)
{
    heap_node **nodes;
    long id, diff, skew = 0;
#ifdef  HEAP_DEBUG_SKEW
    long skewsq = 0;
#endif /* HEAP_DEBUG_SKEW */
    float norm = 0;
    unsigned long max;

    /*
     * Lock the heap to copy it.  If replacing it need to keep the heap locked
     * until we are all done.
     */
    mutex_lock(hp->lock);

    max = heap_nodes(heap);

    /*
     * Copy the heap nodes to a new storage area for offline sorting.
     */
    nodes = xmalloc(max * sizeof(heap_node *));
    memcpy(nodes, heap->nodes, max * sizeof(heap_node *));

    if (replace == 0) {
        /*
         * Unlock the heap to allow updates from other threads before the sort.
         * This allows other heap operations to proceed concurrently with the
         * heap skew computation on the heap at the time of the call ...
         */
        mutex_unlock(hp->lock);
    }
    qsort(nodes, max, sizeof(heap_node *), compare_heap_keys);

    for (id = 0; id < max; id++) {
        diff = id - nodes[id]->id;
        skew += abs(diff);

#ifdef  HEAP_DEBUG_SKEW
        skewsq += diff * diff;
#ifdef  HEAP_DEBUG_ALL
        printf("%d\tKey = %f, diff = %d\n", id, nodes[id]->key, diff);
#endif /* HEAP_DEBUG */
#endif /* HEAP_DEBUG_SKEW */
    }

    if (replace != 0) {
        /*
         * Replace the original heap with the newly sorted heap and let it
         * continue.  Then compute the skew using the copy of the previous heap
         * which we maintain as private data.
         */
        memcpy(heap->nodes, nodes, max * sizeof(heap_node *));

        for (id = 0; id < max; id++) {
            /*
             * Fix up all the ID values in the copied nodes.
             */
            heap->nodes[id]->id = id;
        }

        mutex_unlock(hp->lock);
    }
    /*
     * The skew value is normalized to a range of [0..1]; the distribution
     * appears to be a skewed Gaussian distribution.  For random insertions
     * into a heap the normalized skew will be slightly less than 0.5.  The
     * maximum value of skew/N^2 (for any value of N) is about 0.39 and is
     * fairly stable.
     */
    norm = skew * 2.56 / (max * max);

    /*
     * Free the nodes array; note this is just an array of pointers, not data!
     */
    xfree(nodes);
    return norm;
}

#endif /* MEASURE_HEAP_SKEW */

