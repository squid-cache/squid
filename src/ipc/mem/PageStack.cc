/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"

#include "Debug.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"

#include <cmath>
#include <algorithm>

/*

Ipc::Mem::IdSet and related code maintains a perfect full binary tree structure:

         (l,r)
           /\
    (ll,lr)  (rl,rr)
       /\      /\
      L1 L2   L3 L4

where

    * (l,r) is an always-present root node;
    * inner nodes, including the root one, count the total number of available
      IDs in the leaf nodes of the left and right subtrees (e.g., r = rl + rr);
    * leaf nodes are bitsets of available IDs (e.g., rl = number of 1s in L3);
      all leaf nodes are always present.

The above sample tree would be stored as seven 64-bit atomic integers:
    (l,r), (ll,lr), (rl,rr), L1, L2, L3, L4

*/

namespace Ipc
{

namespace Mem
{

/// the maximum number of pages that a leaf node can store
static const IdSet::size_type BitsPerLeaf = 64;

class IdSetPosition
{
public:
    using size_type = IdSet::size_type;

    IdSetPosition() = default; ///< root node position
    IdSetPosition(size_type aLevel, size_type anOffset);

    /// whether we are at the top of the tree
    bool atRoot() const { return !level && !offset; }

    /// which direction is this position from our parent node
    IdSetNavigationDirection ascendDirection() const;

    /// the number of levels above us (e.g., zero for the root node)
    IdSet::size_type level = 0;
    /// the number of nodes (at our level) to the left of us
    IdSet::size_type offset = 0;
};

/// a helper class to perform inner node manipulation for IdSet
class IdSetInnerNode
{
public:
    using size_type = IdSet::size_type;
    typedef uint64_t Packed; ///< (atomically) stored serialized value

    /// de-serializes a given value
    static IdSetInnerNode Unpack(Packed packed);

    IdSetInnerNode() = default;
    IdSetInnerNode(size_type left, size_type right);

    /// returns a serializes value suitable for shared memory storage
    Packed pack() const { return (static_cast<Packed>(left) << 32) | right; }

    size_type left = 0; ///< the number of available IDs in the left subtree
    size_type right = 0; ///< the number of available IDs in the right subtree
};

} // namespace Mem

} // namespace Ipc

/* Ipc::Mem::IdSetPosition */

Ipc::Mem::IdSetPosition::IdSetPosition(size_type aLevel, size_type anOffset):
    level(aLevel),
    offset(anOffset)
{
}

Ipc::Mem::IdSetNavigationDirection
Ipc::Mem::IdSetPosition::ascendDirection() const
{
    return (offset % 2 == 0) ? dirLeft : dirRight;
}

/* Ipc::Mem::IdSetMeasurements */

Ipc::Mem::IdSetMeasurements::IdSetMeasurements(const size_type aCapacity)
{
    capacity = aCapacity;

    // For simplicity, we want a perfect full binary tree with root and leaves.
    // We could compute all this with log2() calls, but rounding and honoring
    // root+leaves minimums make that approach more complex than this fast loop.
    requestedLeafNodeCount = (capacity + (BitsPerLeaf-1))/BitsPerLeaf;
    treeHeight = 1+1; // the root level plus the leaf nodes level
    leafNodeCount = 2; // the root node can have only two leaf nodes
    while (leafNodeCount < requestedLeafNodeCount) {
        leafNodeCount *= 2;
        ++treeHeight;
    }
    innerLevelCount = treeHeight - 1;

    debugs(54, 5, "rounded capacity up from " << capacity << " to " << (leafNodeCount*BitsPerLeaf));

    // we do (1 << level) when computing 32-bit IdSetInnerNode::left
    assert(treeHeight < 32);
}

/* Ipc::Mem::IdSetInnerNode */

Ipc::Mem::IdSetInnerNode::IdSetInnerNode(size_type aLeft, size_type aRight):
    left(aLeft),
    right(aRight)
{
}

Ipc::Mem::IdSetInnerNode
Ipc::Mem::IdSetInnerNode::Unpack(Packed packed)
{
    // truncation during the cast is intentional here
    return IdSetInnerNode(packed >> 32, static_cast<uint32_t>(packed));
}

/* Ipc::Mem::IdSet */

Ipc::Mem::IdSet::IdSet(const size_type capacity):
    measurements(capacity),
    nodes_(capacity)
{
    // For valueAddress() to be able to return a raw uint64_t pointer, the
    // atomic wrappers in nodes_ must be zero-size. Check the best we can. Once.
    static_assert(sizeof(StoredNode) == sizeof(Node), "atomic locks use no storage");
    assert(StoredNode().is_lock_free());

    makeFullBeforeSharing();
}

void
Ipc::Mem::IdSet::makeFullBeforeSharing()
{
    // initially, all IDs are marked as available
    fillAllNodes();

    // ... but IDs beyond the requested capacity should not be available
    if (measurements.capacity != measurements.leafNodeCount*BitsPerLeaf)
        truncateExtras();
}

/// populates the entire allocated tree with available IDs
/// may exceed the requested capacity; \see truncateExtras()
void
Ipc::Mem::IdSet::fillAllNodes()
{
    // leaf nodes
    auto pos = Position(measurements.treeHeight-1, 0);
    const auto allOnes = ~uint64_t(0);
    std::fill_n(valueAddress(pos), measurements.leafNodeCount, allOnes);

    // inner nodes, starting from the bottom of the tree
    auto nodesAtLevel = measurements.leafNodeCount/2;
    auto pagesBelow = BitsPerLeaf;
    do {
        pos = ascend(pos);
        const auto value = IdSetInnerNode(pagesBelow, pagesBelow).pack();
        std::fill_n(valueAddress(pos), nodesAtLevel, value);
        nodesAtLevel /= 2;
        pagesBelow *= 2;
    } while (!pos.atRoot());
}

/// effectively removes IDs that exceed the requested capacity after makeFull()
void
Ipc::Mem::IdSet::truncateExtras()
{
    // leaf nodes
    // start with the left-most leaf that should have some 0s; it may even have
    // no 1s at all (i.e. be completely unused)
    auto pos = Position(measurements.treeHeight-1, measurements.capacity/BitsPerLeaf);
    leafTruncate(pos, measurements.capacity % BitsPerLeaf);
    const auto rightLeaves = measurements.leafNodeCount - measurements.requestedLeafNodeCount;
    // this zeroing of the leaf nodes to the right from pos is only necessary to
    // trigger asserts if the code dealing with the inner node counters is buggy
    if (rightLeaves > 1)
        std::fill_n(valueAddress(pos) + 1, rightLeaves-1, 0);

    // inner nodes, starting from the bottom of the tree; optimization: only
    // adjusting nodes on the way up from the first leaf-with-0s position
    auto toSubtract = BitsPerLeaf - (measurements.capacity % BitsPerLeaf);
    do {
        const auto direction = pos.ascendDirection();
        pos = ascend(pos);
        toSubtract = innerTruncate(pos, direction, toSubtract);
    } while (!pos.atRoot());
}

/// fill the leaf node at a given position with 0s, leaving only idsToKeep IDs
void
Ipc::Mem::IdSet::leafTruncate(const Position pos, const size_type idsToKeep)
{
    Node &node = *valueAddress(pos); // no auto to simplify the asserts() below
    assert(node == std::numeric_limits<Node>::max()); // all 1s
    static_assert(std::is_unsigned<Node>::value, "right shift prepends 0s");
    node >>= BitsPerLeaf - idsToKeep;
    // node can be anything here, including all 0s and all 1s
}

/// accounts for toSubtract IDs removal from a subtree in the given direction of
/// the given position
/// \returns the number of IDs to subtract from the parent node
Ipc::Mem::IdSet::size_type
Ipc::Mem::IdSet::innerTruncate(const Position pos, const NavigationDirection dir, const size_type toSubtract)
{
    auto *valuePtr = valueAddress(pos);
    auto value = IdSetInnerNode::Unpack(*valuePtr);
    size_type toSubtractNext = 0;
    if (dir == dirLeft) {
        toSubtractNext = toSubtract + value.right;
        assert(value.left >= toSubtract);
        value.left -= toSubtract;
        value.right = 0;
    } else {
        assert(dir == dirRight);
        toSubtractNext = toSubtract;
        assert(value.right >= toSubtract);
        // value.left is unchanged; we have only adjusted the right branch
        value.right -= toSubtract;
    }
    *valuePtr = value.pack();
    return toSubtractNext;
}

/// accounts for an ID added to subtree in the given dir from the given position
void
Ipc::Mem::IdSet::innerPush(const Position pos, const NavigationDirection dir)
{
    // either left or right component will be true/1; the other will be false/0
    const auto increment = IdSetInnerNode(dir == dirLeft, dir == dirRight).pack();
    const auto previousValue = nodeAt(pos).fetch_add(increment);
    // no overflows
    assert(previousValue <= std::numeric_limits<Node>::max() - increment);
}

/// accounts for future ID removal from a subtree of the given position
/// \returns the direction of the subtree chosen to relinquish the ID
Ipc::Mem::IdSet::NavigationDirection
Ipc::Mem::IdSet::innerPop(const Position pos)
{
    NavigationDirection direction = dirNone;

    auto &node = nodeAt(pos);
    auto oldValue = node.load();
    IdSetInnerNode newValue;
    do {
        newValue = IdSetInnerNode::Unpack(oldValue);
        if (newValue.left) {
            --newValue.left;
            direction = dirLeft;
        } else if (newValue.right) {
            --newValue.right;
            direction = dirRight;
        } else {
            return dirEnd;
        }
    } while (!node.compare_exchange_weak(oldValue, newValue.pack()));

    assert(direction == dirLeft || direction == dirRight);
    return direction;
}

/// adds the given ID to the leaf node at the given position
void
Ipc::Mem::IdSet::leafPush(const Position pos, const size_type id)
{
    const auto mask = Node(1) << (id % BitsPerLeaf);
    const auto oldValue = nodeAt(pos).fetch_or(mask);
    // this was a new entry
    assert((oldValue & mask) == 0);
}

// TODO: After switching to C++20, use countr_zero() which may compile to a
// single TZCNT assembly instruction on modern CPUs.
/// a temporary C++20 countr_zero() replacement
static inline
int trailingZeros(uint64_t x)
{
    if (!x)
        return 64;
    int count = 0;
    for (uint64_t mask = 1; !(x & mask); mask <<= 1)
        ++count;
    return count;
}

/// extracts and returns an ID from the leaf node at the given position
Ipc::Mem::IdSet::size_type
Ipc::Mem::IdSet::leafPop(const Position pos)
{
    auto &node = nodeAt(pos);
    auto oldValue = node.load();
    Node newValue;
    do {
        assert(oldValue > 0);
        const auto mask = oldValue - 1; // flips the rightmost 1 and trailing 0s
        newValue = oldValue & mask; // clears the rightmost 1
    } while (!node.compare_exchange_weak(oldValue, newValue));

    return pos.offset*BitsPerLeaf + trailingZeros(oldValue);
}

/// \returns the position of a parent node of the node at the given position
Ipc::Mem::IdSet::Position
Ipc::Mem::IdSet::ascend(Position pos)
{
    assert(pos.level > 0);
    --pos.level;
    pos.offset /= 2;
    return pos;
}

/// \returns the position of a child node in the given direction of the parent
/// node at the given position
Ipc::Mem::IdSet::Position
Ipc::Mem::IdSet::descend(Position pos, const NavigationDirection direction)
{
    assert(pos.level < measurements.treeHeight);
    ++pos.level;

    pos.offset *= 2;
    if (direction == dirRight)
        ++pos.offset;
    else
        assert(direction == dirLeft);

    return pos;
}

/// \returns the atomic node (either inner or leaf) at the given position
Ipc::Mem::IdSet::StoredNode &
Ipc::Mem::IdSet::nodeAt(const Position pos)
{
    assert(pos.level < measurements.treeHeight);
    // n = 2^(h+1) - 1 with h = level-1
    const auto nodesAbove = (1U << pos.level) - 1;

    // the second clause is for the special case of a root node
    assert(pos.offset < nodesAbove*2 || (pos.atRoot() && nodesAbove == 0));
    const auto nodesToTheLeft = pos.offset;

    const size_t nodesBefore = nodesAbove + nodesToTheLeft;
    assert(nodesBefore < measurements.nodeCount());
    return nodes_[nodesBefore];
}

/// \returns the location of the raw (inner or leaf) node at the given position
Ipc::Mem::IdSet::Node *
Ipc::Mem::IdSet::valueAddress(const Position pos)
{
    // IdSet() constructor asserts that this frequent reinterpret_cast is safe
    return &reinterpret_cast<Node&>(nodeAt(pos));
}

bool
Ipc::Mem::IdSet::pop(size_type &id)
{
    Position rootPos;
    const auto directionFromRoot = innerPop(rootPos);
    if (directionFromRoot == dirEnd)
        return false; // an empty tree

    auto pos = descend(rootPos, directionFromRoot);
    for (size_t level = 1; level < measurements.innerLevelCount; ++level) {
        const auto direction = innerPop(pos);
        pos = descend(pos, direction);
    }

    id = leafPop(pos);
    return true;
}

void
Ipc::Mem::IdSet::push(const size_type id)
{
    const auto offsetAtLeafLevel = id/BitsPerLeaf;
    auto pos = Position(measurements.innerLevelCount, offsetAtLeafLevel);
    leafPush(pos, id);

    do {
        const auto direction = pos.ascendDirection();
        pos = ascend(pos);
        innerPush(pos, direction);
    } while (!pos.atRoot());
}

size_t
Ipc::Mem::IdSet::MemorySize(const size_type capacity)
{
    const IdSetMeasurements measurements(capacity);
    // Adding sizeof(IdSet) double-counts the first node but it is better to
    // overestimate (a little) than to underestimate our memory needs due to
    // padding, new data members, etc.
    return sizeof(IdSet) + measurements.nodeCount() * sizeof(StoredNode);
}

/* Ipc::Mem::PageStack */

Ipc::Mem::PageStack::PageStack(const PoolId aPoolId, const PageCount aCapacity, const size_t aPageSize):
    thePoolId(aPoolId), capacity_(aCapacity), thePageSize(aPageSize),
    size_(0),
    ids_(capacity_)
{
    size_ = capacity_;
}

bool
Ipc::Mem::PageStack::pop(PageId &page)
{
    assert(!page);

    if (!capacity_)
        return false;

    IdSet::size_type pageIndex = 0;
    if (!ids_.pop(pageIndex))
        return false;

    // must decrement after removing the page to avoid underflow
    const auto newSize = --size_;
    assert(newSize < capacity_);

    page.number = pageIndex + 1;
    page.pool = thePoolId;
    debugs(54, 8, page << " size: " << newSize);
    assert(pageIdIsValid(page));
    return true;
}

void
Ipc::Mem::PageStack::push(PageId &page)
{
    debugs(54, 8, page);
    assert(page);
    assert(pageIdIsValid(page));

    // must increment before inserting the page to avoid underflow in pop()
    const auto newSize = ++size_;
    assert(newSize <= capacity_);

    const auto pageIndex = page.number - 1;
    ids_.push(pageIndex);

    debugs(54, 8, page << " size: " << newSize);
    page = PageId();
}

bool
Ipc::Mem::PageStack::pageIdIsValid(const PageId &page) const
{
    return page.pool == thePoolId &&
           0 < page.number && page.number <= capacity();
}

size_t
Ipc::Mem::PageStack::sharedMemorySize() const
{
    return SharedMemorySize(thePoolId, capacity_, thePageSize);
}

size_t
Ipc::Mem::PageStack::SharedMemorySize(const PoolId, const PageCount capacity, const size_t pageSize)
{
    const auto levelsSize = PageId::maxPurpose * sizeof(Levels_t);
    const size_t pagesDataSize = capacity * pageSize;
    return StackSize(capacity) + LevelsPaddingSize(capacity) + levelsSize + pagesDataSize;
}

size_t
Ipc::Mem::PageStack::StackSize(const PageCount capacity)
{
    // Adding sizeof(PageStack) double-counts the fixed portion of the ids_ data
    // member but it is better to overestimate (a little) than to underestimate
    // our memory needs due to padding, new data members, etc.
    return sizeof(PageStack) + IdSet::MemorySize(capacity);
}

size_t
Ipc::Mem::PageStack::stackSize() const
{
    return StackSize(capacity_);
}

size_t
Ipc::Mem::PageStack::LevelsPaddingSize(const PageCount capacity)
{
    const auto displacement = StackSize(capacity) % alignof(Levels_t);
    return displacement ? alignof(Levels_t) - displacement : 0;
}

