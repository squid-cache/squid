/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_IPC_QUEUE_H
#define SQUID_SRC_IPC_QUEUE_H

#include "base/InstanceId.h"
#include "debug/Stream.h"
#include "ipc/mem/FlexibleArray.h"
#include "ipc/mem/Pointer.h"
#include "util.h"

#include <algorithm>
#include <atomic>

class String;

namespace Ipc
{

/// State of the reading end of a queue (i.e., of the code calling pop()).
/// Multiple queues attached to one reader share this state.
class QueueReader
{
public:
    QueueReader(); // the initial state is "blocked without a signal"

    /// whether the reader is waiting for a notification signal
    bool blocked() const { return popBlocked.load(); }

    /// \copydoc popSignal
    bool signaled() const { return popSignal.load(); }

    /// marks the reader as blocked, waiting for a notification signal
    void block() { popBlocked.store(true); }

    /// removes the block() effects
    void unblock() { popBlocked.store(false); }

    /// if reader is blocked and not notified, marks the notification signal
    /// as sent and not received, returning true; otherwise, returns false
    bool raiseSignal() { return blocked() && !popSignal.exchange(true); }

    /// marks sent reader notification as received (also removes pop blocking)
    void clearSignal() { unblock(); popSignal.store(false); }

private:
    std::atomic<bool> popBlocked; ///< whether the reader is blocked on pop()
    std::atomic<bool> popSignal; ///< whether writer has sent and reader has not received notification

public:
    typedef std::atomic<int> Rate; ///< pop()s per second
    Rate rateLimit; ///< pop()s per second limit if positive

    // we need a signed atomic type because balance may get negative
    typedef std::atomic<int> AtomicSignedMsec;
    typedef AtomicSignedMsec Balance;
    /// how far ahead the reader is compared to a perfect read/sec event rate
    Balance balance;

    /// unique ID for debugging which reader is used (works across processes)
    const InstanceId<QueueReader> id;
};

/// shared array of QueueReaders
class QueueReaders
{
public:
    QueueReaders(const int aCapacity);
    size_t sharedMemorySize() const;
    static size_t SharedMemorySize(const int capacity);

    const int theCapacity; /// number of readers
    Ipc::Mem::FlexibleArray<QueueReader> theReaders; /// readers
};

/**
 * Lockless fixed-capacity queue for a single writer and a single reader.
 *
 * If the queue is empty, the reader is considered "blocked" and needs
 * an out-of-band notification message to notice the next pushed item.
 *
 * Current implementation assumes that the writer cannot get blocked: if the
 * queue is full, the writer will just not push and come back later (with a
 * different value). We can add support for blocked writers if needed.
 */
class OneToOneUniQueue
{
public:
    // pop() and push() exceptions; TODO: use TextException instead
    class Full {};
    class ItemTooLarge {};

    OneToOneUniQueue(const unsigned int aMaxItemSize, const int aCapacity);

    unsigned int maxItemSize() const { return theMaxItemSize; }
    int size() const { return theSize; }
    int capacity() const { return theCapacity; }
    int sharedMemorySize() const { return Items2Bytes(theMaxItemSize, theCapacity); }

    bool empty() const { return !theSize; }
    bool full() const { return theSize == theCapacity; }

    static int Bytes2Items(const unsigned int maxItemSize, int size);
    static int Items2Bytes(const unsigned int maxItemSize, const int size);

    /// returns true iff the value was set; [un]blocks the reader as needed
    template<class Value> bool pop(Value &value, QueueReader *const reader = nullptr);

    /// returns true iff the caller must notify the reader of the pushed item
    template<class Value> bool push(const Value &value, QueueReader *const reader = nullptr);

    /// returns true iff the value was set; the value may be stale!
    template<class Value> bool peek(Value &value) const;

    /// prints incoming queue state; suitable for cache manager reports
    template<class Value> void statIn(std::ostream &, int localProcessId, int remoteProcessId) const;
    /// prints outgoing queue state; suitable for cache manager reports
    template<class Value> void statOut(std::ostream &, int localProcessId, int remoteProcessId) const;

private:
    void statOpen(std::ostream &, const char *inLabel, const char *outLabel, uint32_t count) const;
    void statClose(std::ostream &) const;
    template<class Value> void statSamples(std::ostream &, unsigned int start, uint32_t size) const;
    template<class Value> void statRange(std::ostream &, unsigned int start, uint32_t n) const;

    // optimization: these non-std::atomic data members are in shared memory,
    // but each is used only by one process (aside from obscured reporting)
    unsigned int theIn; ///< current push() position; reporting aside, used only in push()
    unsigned int theOut; ///< current pop() position; reporting aside, used only in pop()/peek()

    std::atomic<uint32_t> theSize; ///< number of items in the queue
    const unsigned int theMaxItemSize; ///< maximum item size
    const uint32_t theCapacity; ///< maximum number of items, i.e. theBuffer size

    char theBuffer[];
};

/// shared array of OneToOneUniQueues
class OneToOneUniQueues
{
public:
    OneToOneUniQueues(const int aCapacity, const unsigned int maxItemSize, const int queueCapacity);

    size_t sharedMemorySize() const;
    static size_t SharedMemorySize(const int capacity, const unsigned int maxItemSize, const int queueCapacity);

    const OneToOneUniQueue &operator [](const int index) const;
    inline OneToOneUniQueue &operator [](const int index);

private:
    inline const OneToOneUniQueue &front() const;

public:
    const int theCapacity; /// number of OneToOneUniQueues
};

/**
 * Base class for lockless fixed-capacity bidirectional queues for a
 * limited number processes.
 */
class BaseMultiQueue
{
public:
    BaseMultiQueue(const int aLocalProcessId);
    virtual ~BaseMultiQueue() {}

    /// clears the reader notification received by the local process from the remote process
    void clearReaderSignal(const int remoteProcessId);

    /// clears all reader notifications received by the local process
    void clearAllReaderSignals();

    /// picks a process and calls OneToOneUniQueue::pop() using its queue
    template <class Value> bool pop(int &remoteProcessId, Value &value);

    /// calls OneToOneUniQueue::push() using the given process queue
    template <class Value> bool push(const int remoteProcessId, const Value &value);

    /// peeks at the item likely to be pop()ed next
    template<class Value> bool peek(int &remoteProcessId, Value &value) const;

    /// prints current state; suitable for cache manager reports
    template<class Value> void stat(std::ostream &) const;

    /// returns local reader's balance
    QueueReader::Balance &localBalance() { return localReader().balance; }

    /// returns reader's balance for a given remote process
    const QueueReader::Balance &balance(const int remoteProcessId) const;

    /// returns local reader's rate limit
    QueueReader::Rate &localRateLimit() { return localReader().rateLimit; }

    /// returns reader's rate limit for a given remote process
    const QueueReader::Rate &rateLimit(const int remoteProcessId) const;

    /// number of items in incoming queue from a given remote process
    int inSize(const int remoteProcessId) const { return inQueue(remoteProcessId).size(); }

    /// number of items in outgoing queue to a given remote process
    int outSize(const int remoteProcessId) const { return outQueue(remoteProcessId).size(); }

protected:
    /// incoming queue from a given remote process
    virtual const OneToOneUniQueue &inQueue(const int remoteProcessId) const = 0;
    OneToOneUniQueue &inQueue(const int remoteProcessId);

    /// outgoing queue to a given remote process
    virtual const OneToOneUniQueue &outQueue(const int remoteProcessId) const = 0;
    OneToOneUniQueue &outQueue(const int remoteProcessId);

    virtual const QueueReader &localReader() const = 0;
    QueueReader &localReader();

    virtual const QueueReader &remoteReader(const int remoteProcessId) const = 0;
    QueueReader &remoteReader(const int remoteProcessId);

    virtual int remotesCount() const = 0;
    virtual int remotesIdOffset() const = 0;

protected:
    const int theLocalProcessId; ///< process ID of this queue

private:
    int theLastPopProcessId; ///< the ID of the last process we tried to pop() from
};

/**
 * Lockless fixed-capacity bidirectional queue for a limited number
 * processes. Allows communication between two groups of processes:
 * any process in one group may send data to and receive from any
 * process in another group, but processes in the same group can not
 * communicate. Process in each group has a unique integer ID in
 * [groupIdOffset, groupIdOffset + groupSize) range.
 */
class FewToFewBiQueue: public BaseMultiQueue
{
public:
    typedef OneToOneUniQueue::Full Full;
    typedef OneToOneUniQueue::ItemTooLarge ItemTooLarge;

private:
    /// Shared metadata for FewToFewBiQueue
    struct Metadata {
        Metadata(const int aGroupASize, const int aGroupAIdOffset, const int aGroupBSize, const int aGroupBIdOffset);
        size_t sharedMemorySize() const { return sizeof(*this); }
        static size_t SharedMemorySize(const int, const int, const int, const int) { return sizeof(Metadata); }

        const int theGroupASize;
        const int theGroupAIdOffset;
        const int theGroupBSize;
        const int theGroupBIdOffset;
    };

public:
    class Owner
    {
    public:
        Owner(const String &id, const int groupASize, const int groupAIdOffset, const int groupBSize, const int groupBIdOffset, const unsigned int maxItemSize, const int capacity);
        ~Owner();

    private:
        Mem::Owner<Metadata> *const metadataOwner;
        Mem::Owner<OneToOneUniQueues> *const queuesOwner;
        Mem::Owner<QueueReaders> *const readersOwner;
    };

    static Owner *Init(const String &id, const int groupASize, const int groupAIdOffset, const int groupBSize, const int groupBIdOffset, const unsigned int maxItemSize, const int capacity);

    enum Group { groupA = 0, groupB = 1 };
    FewToFewBiQueue(const String &id, const Group aLocalGroup, const int aLocalProcessId);

    /// maximum number of items in the queue
    static int MaxItemsCount(const int groupASize, const int groupBSize, const int capacity);

    /// finds the oldest item in incoming and outgoing queues between
    /// us and the given remote process
    template<class Value> bool findOldest(const int remoteProcessId, Value &value) const;

protected:
    const OneToOneUniQueue &inQueue(const int remoteProcessId) const override;
    const OneToOneUniQueue &outQueue(const int remoteProcessId) const override;
    const QueueReader &localReader() const override;
    const QueueReader &remoteReader(const int processId) const override;
    int remotesCount() const override;
    int remotesIdOffset() const override;

private:
    bool validProcessId(const Group group, const int processId) const;
    int oneToOneQueueIndex(const Group fromGroup, const int fromProcessId, const Group toGroup, const int toProcessId) const;
    const OneToOneUniQueue &oneToOneQueue(const Group fromGroup, const int fromProcessId, const Group toGroup, const int toProcessId) const;
    int readerIndex(const Group group, const int processId) const;
    Group localGroup() const { return theLocalGroup; }
    Group remoteGroup() const { return theLocalGroup == groupA ? groupB : groupA; }

private:
    const Mem::Pointer<Metadata> metadata; ///< shared metadata
    const Mem::Pointer<OneToOneUniQueues> queues; ///< unidirection one-to-one queues
    const Mem::Pointer<QueueReaders> readers; ///< readers array

    const Group theLocalGroup; ///< group of this queue
};

/**
 * Lockless fixed-capacity bidirectional queue for a limited number
 * processes. Any process may send data to and receive from any other
 * process (including itself). Each process has a unique integer ID in
 * [processIdOffset, processIdOffset + processCount) range.
 */
class MultiQueue: public BaseMultiQueue
{
public:
    typedef OneToOneUniQueue::Full Full;
    typedef OneToOneUniQueue::ItemTooLarge ItemTooLarge;

private:
    /// Shared metadata for MultiQueue
    struct Metadata {
        Metadata(const int aProcessCount, const int aProcessIdOffset);
        size_t sharedMemorySize() const { return sizeof(*this); }
        static size_t SharedMemorySize(const int, const int) { return sizeof(Metadata); }

        const int theProcessCount;
        const int theProcessIdOffset;
    };

public:
    class Owner
    {
    public:
        Owner(const String &id, const int processCount, const int processIdOffset, const unsigned int maxItemSize, const int capacity);
        ~Owner();

    private:
        Mem::Owner<Metadata> *const metadataOwner;
        Mem::Owner<OneToOneUniQueues> *const queuesOwner;
        Mem::Owner<QueueReaders> *const readersOwner;
    };

    static Owner *Init(const String &id, const int processCount, const int processIdOffset, const unsigned int maxItemSize, const int capacity);

    MultiQueue(const String &id, const int localProcessId);

protected:
    const OneToOneUniQueue &inQueue(const int remoteProcessId) const override;
    const OneToOneUniQueue &outQueue(const int remoteProcessId) const override;
    const QueueReader &localReader() const override;
    const QueueReader &remoteReader(const int remoteProcessId) const override;
    int remotesCount() const override;
    int remotesIdOffset() const override;

private:
    bool validProcessId(const int processId) const;
    const OneToOneUniQueue &oneToOneQueue(const int fromProcessId, const int toProcessId) const;
    const QueueReader &reader(const int processId) const;

private:
    const Mem::Pointer<Metadata> metadata; ///< shared metadata
    const Mem::Pointer<OneToOneUniQueues> queues; ///< unidirection one-to-one queues
    const Mem::Pointer<QueueReaders> readers; ///< readers array
};

// OneToOneUniQueue

template <class Value>
bool
OneToOneUniQueue::pop(Value &value, QueueReader *const reader)
{
    if (sizeof(value) > theMaxItemSize)
        throw ItemTooLarge();

    // A writer might push between the empty test and block() below, so we do
    // not return false right after calling block(), but test again.
    if (empty()) {
        if (!reader)
            return false;

        reader->block();
        // A writer might push between the empty test and block() below,
        // so we must test again as such a writer will not signal us.
        if (empty())
            return false;
    }

    if (reader)
        reader->unblock();

    const unsigned int pos = (theOut++ % theCapacity) * theMaxItemSize;
    memcpy(&value, theBuffer + pos, sizeof(value));
    --theSize;

    return true;
}

template <class Value>
bool
OneToOneUniQueue::peek(Value &value) const
{
    if (sizeof(value) > theMaxItemSize)
        throw ItemTooLarge();

    if (empty())
        return false;

    // the reader may pop() before we copy; making this method imprecise
    const unsigned int pos = (theOut % theCapacity) * theMaxItemSize;
    memcpy(&value, theBuffer + pos, sizeof(value));
    return true;
}

template <class Value>
bool
OneToOneUniQueue::push(const Value &value, QueueReader *const reader)
{
    if (sizeof(value) > theMaxItemSize)
        throw ItemTooLarge();

    if (full())
        throw Full();

    const unsigned int pos = theIn++ % theCapacity * theMaxItemSize;
    memcpy(theBuffer + pos, &value, sizeof(value));
    const bool wasEmpty = !theSize++;

    return wasEmpty && (!reader || reader->raiseSignal());
}

template <class Value>
void
OneToOneUniQueue::statIn(std::ostream &os, const int localProcessId, const int remoteProcessId) const
{
    os << "  kid" << localProcessId << " receiving from kid" << remoteProcessId << ": ";
    // Nobody can modify our theOut so, after capturing some valid theSize value
    // in count, we can reliably report all [theOut, theOut+count) items that
    // were queued at theSize capturing time. We will miss new items push()ed by
    // the other side, but it is OK -- we report state at the capturing time.
    const auto count = theSize.load();
    statOpen(os, "other", "popIndex", count);
    statSamples<Value>(os, theOut, count);
    statClose(os);
}

template <class Value>
void
OneToOneUniQueue::statOut(std::ostream &os, const int localProcessId, const int remoteProcessId) const
{
    os << "  kid" << localProcessId << " sending to kid" << remoteProcessId << ": ";
    // Nobody can modify our theIn so, after capturing some valid theSize value
    // in count, we can reliably report all [theIn-count, theIn) items that were
    // queued at theSize capturing time. We may report items already pop()ed by
    // the other side, but that is OK because pop() does not modify items -- it
    // only increments theOut.
    const auto count = theSize.load();
    statOpen(os, "pushIndex", "other", count);
    statSamples<Value>(os, theIn - count, count); // unsigned offset underflow OK
    statClose(os);
}

/// report a sample of [start, start + size) items
template <class Value>
void
OneToOneUniQueue::statSamples(std::ostream &os, const unsigned int start, const uint32_t count) const
{
    if (!count) {
        os << " ";
        return;
    }

    os << ", items: [\n";
    // report a few leading and trailing items, without repetitions
    const auto sampleSize = std::min(3U, count); // leading (and max) sample
    statRange<Value>(os, start, sampleSize);
    if (sampleSize < count) { // the first sample did not show some items
        // The `start` offset aside, the first sample reported all items
        // below the sampleSize offset. The second sample needs to report
        // the last sampleSize items (i.e. starting at count-sampleSize
        // offset) except those already reported by the first sample.
        const auto secondSampleOffset = std::max(sampleSize, count - sampleSize);
        const auto secondSampleSize = std::min(sampleSize, count - sampleSize);

        // but first we print a sample separator, unless there are no items
        // between the samples or the separator hides the only unsampled item
        const auto bothSamples = sampleSize + secondSampleSize;
        if (bothSamples + 1U == count)
            statRange<Value>(os, start + sampleSize, 1);
        else if (count > bothSamples)
            os << "    # ... " << (count - bothSamples) << " items not shown ...\n";

        statRange<Value>(os, start + secondSampleOffset, secondSampleSize);
    }
    os << "  ]";
}

/// statSamples() helper that reports n items from start
template <class Value>
void
OneToOneUniQueue::statRange(std::ostream &os, const unsigned int start, const uint32_t n) const
{
    assert(sizeof(Value) <= theMaxItemSize);
    auto offset = start;
    for (uint32_t i = 0; i < n; ++i) {
        // XXX: Throughout this C++ header, these overflow wrapping tricks work
        // only because theCapacity currently happens to be a power of 2 (e.g.,
        // the highest offset (0xF...FFF) % 3 is 0 and so is the next offset).
        const auto pos = (offset++ % theCapacity) * theMaxItemSize;
        Value value;
        memcpy(&value, theBuffer + pos, sizeof(value));
        os << "    { ";
        value.stat(os);
        os << " },\n";
    }
}

// OneToOneUniQueues

inline OneToOneUniQueue &
OneToOneUniQueues::operator [](const int index)
{
    return const_cast<OneToOneUniQueue &>((*const_cast<const OneToOneUniQueues *>(this))[index]);
}

inline const OneToOneUniQueue &
OneToOneUniQueues::front() const
{
    const char *const queue =
        reinterpret_cast<const char *>(this) + sizeof(*this);
    return *reinterpret_cast<const OneToOneUniQueue *>(queue);
}

// BaseMultiQueue

template <class Value>
bool
BaseMultiQueue::pop(int &remoteProcessId, Value &value)
{
    // iterate all remote processes, starting after the one we visited last
    for (int i = 0; i < remotesCount(); ++i) {
        if (++theLastPopProcessId >= remotesIdOffset() + remotesCount())
            theLastPopProcessId = remotesIdOffset();
        OneToOneUniQueue &queue = inQueue(theLastPopProcessId);
        if (queue.pop(value, &localReader())) {
            remoteProcessId = theLastPopProcessId;
            debugs(54, 7, "popped from " << remoteProcessId << " to " << theLocalProcessId << " at " << queue.size());
            return true;
        }
    }
    return false; // no process had anything to pop
}

template <class Value>
bool
BaseMultiQueue::push(const int remoteProcessId, const Value &value)
{
    OneToOneUniQueue &remoteQueue = outQueue(remoteProcessId);
    QueueReader &reader = remoteReader(remoteProcessId);
    debugs(54, 7, "pushing from " << theLocalProcessId << " to " << remoteProcessId << " at " << remoteQueue.size());
    return remoteQueue.push(value, &reader);
}

template <class Value>
bool
BaseMultiQueue::peek(int &remoteProcessId, Value &value) const
{
    // mimic FewToFewBiQueue::pop() but quit just before popping
    int popProcessId = theLastPopProcessId; // preserve for future pop()
    for (int i = 0; i < remotesCount(); ++i) {
        if (++popProcessId >= remotesIdOffset() + remotesCount())
            popProcessId = remotesIdOffset();
        const OneToOneUniQueue &queue = inQueue(popProcessId);
        if (queue.peek(value)) {
            remoteProcessId = popProcessId;
            return true;
        }
    }
    return false; // most likely, no process had anything to pop
}

template <class Value>
void
BaseMultiQueue::stat(std::ostream &os) const
{
    for (int processId = remotesIdOffset(); processId < remotesIdOffset() + remotesCount(); ++processId) {
        const auto &queue = inQueue(processId);
        queue.statIn<Value>(os, theLocalProcessId, processId);
    }

    os << "\n";

    for (int processId = remotesIdOffset(); processId < remotesIdOffset() + remotesCount(); ++processId) {
        const auto &queue = outQueue(processId);
        queue.statOut<Value>(os, theLocalProcessId, processId);
    }

    os << "\n";

    const auto &reader = localReader();
    os << "  kid" << theLocalProcessId << " reader flags: " <<
       "{ blocked: " << reader.blocked() << ", signaled: " << reader.signaled() << " }\n";
}

// FewToFewBiQueue

template <class Value>
bool
FewToFewBiQueue::findOldest(const int remoteProcessId, Value &value) const
{
    // we may be called before remote process configured its queue end
    if (!validProcessId(remoteGroup(), remoteProcessId))
        return false;

    // we need the oldest value, so start with the incoming, them-to-us queue:
    const OneToOneUniQueue &in = inQueue(remoteProcessId);
    debugs(54, 2, "peeking from " << remoteProcessId << " to " <<
           theLocalProcessId << " at " << in.size());
    if (in.peek(value))
        return true;

    // if the incoming queue is empty, check the outgoing, us-to-them queue:
    const OneToOneUniQueue &out = outQueue(remoteProcessId);
    debugs(54, 2, "peeking from " << theLocalProcessId << " to " <<
           remoteProcessId << " at " << out.size());
    return out.peek(value);
}

} // namespace Ipc

#endif /* SQUID_SRC_IPC_QUEUE_H */

