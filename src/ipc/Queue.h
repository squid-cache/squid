/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_QUEUE_H
#define SQUID_IPC_QUEUE_H

#include "Array.h"
#include "base/InstanceId.h"
#include "ipc/AtomicWord.h"
#include "ipc/mem/Segment.h"
#include "util.h"

class String;

/// State of the reading end of a queue (i.e., of the code calling pop()).
/// Multiple queues attached to one reader share this state.
class QueueReader {
public:
    QueueReader(); // the initial state is "blocked without a signal"

    /// whether the reader is waiting for a notification signal
    bool blocked() const { return popBlocked == 1; }

    /// marks the reader as blocked, waiting for a notification signal
    void block() { popBlocked.swap_if(0, 1); }

    /// removes the block() effects
    void unblock() { popBlocked.swap_if(1, 0); }

    /// if reader is blocked and not notified, marks the notification signal
    /// as sent and not received, returning true; otherwise, returns false
    bool raiseSignal() { return blocked() && popSignal.swap_if(0,1); }

    /// marks sent reader notification as received (also removes pop blocking)
    void clearSignal() { unblock(); popSignal.swap_if(1,0); }

private:
    AtomicWord popBlocked; ///< whether the reader is blocked on pop()
    AtomicWord popSignal; ///< whether writer has sent and reader has not received notification

public:
    /// unique ID for debugging which reader is used (works across processes)
    const InstanceId<QueueReader> id;
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
class OneToOneUniQueue {
public:
    // pop() and push() exceptions; TODO: use TextException instead
    class Full {};
    class ItemTooLarge {};

    OneToOneUniQueue(const String &id, const unsigned int maxItemSize, const int capacity);
    OneToOneUniQueue(const String &id);

    unsigned int maxItemSize() const { return shared->theMaxItemSize; }
    int size() const { return shared->theSize; }
    int capacity() const { return shared->theCapacity; }

    bool empty() const { return !shared->theSize; }
    bool full() const { return shared->theSize == shared->theCapacity; }

    static int Bytes2Items(const unsigned int maxItemSize, int size);
    static int Items2Bytes(const unsigned int maxItemSize, const int size);

    /// returns true iff the value was set; [un]blocks the reader as needed
    template<class Value> bool pop(Value &value);

    /// returns true iff the caller must notify the reader of the pushed item
    template<class Value> bool push(const Value &value);

    QueueReader &reader();
    void reader(QueueReader *aReader);

private:
    struct Shared {
        Shared(const unsigned int aMaxItemSize, const int aCapacity);

        unsigned int theIn; ///< input index, used only in push()
        unsigned int theOut; ///< output index, used only in pop()

        AtomicWord theSize; ///< number of items in the queue
        const unsigned int theMaxItemSize; ///< maximum item size
        const int theCapacity; ///< maximum number of items, i.e. theBuffer size

        char theBuffer[];
    };

    Ipc::Mem::Segment shm; ///< shared memory segment
    Shared *shared; ///< pointer to shared memory
    QueueReader *reader_; ///< the state of the code popping from this queue
};

/// Lockless fixed-capacity bidirectional queue for two processes.
class OneToOneBiQueue {
public:
    typedef OneToOneUniQueue::Full Full;
    typedef OneToOneUniQueue::ItemTooLarge ItemTooLarge;

    /// Create a new shared queue.
    OneToOneBiQueue(const String &id, const unsigned int maxItemSize, const int capacity);
    OneToOneBiQueue(const String &id); ///< Attach to existing shared queue.

    void readers(QueueReader *r1, QueueReader *r2);
    void clearReaderSignal();

    /* wrappers to call the right OneToOneUniQueue method for this process */
    template<class Value> bool pop(Value &value) { return popQueue->pop(value); }
    template<class Value> bool push(const Value &value) { return pushQueue->push(value); }

//private:
    OneToOneUniQueue *const popQueue; ///< queue to pop from for this process
    OneToOneUniQueue *const pushQueue; ///< queue to push to for this process
};

/**
 * Lockless fixed-capacity bidirectional queue for a limited number
 * pricesses. Implements a star topology: Many worker processes
 * communicate with the one central process. The central process uses
 * FewToOneBiQueue object, while workers use OneToOneBiQueue objects
 * created with the Attach() method. Each worker has a unique integer
 * ID in [1, workerCount] range.
 */
class FewToOneBiQueue {
public:
    typedef OneToOneBiQueue::Full Full;
    typedef OneToOneBiQueue::ItemTooLarge ItemTooLarge;

    FewToOneBiQueue(const String &id, const int aWorkerCount, const unsigned int maxItemSize, const int capacity);
    static OneToOneBiQueue *Attach(const String &id, const int workerId);
    ~FewToOneBiQueue();

    bool validWorkerId(const int workerId) const;
    int workerCount() const { return theWorkerCount; }

    /// clears the reader notification received by the disker from worker
    void clearReaderSignal(int workerId);

    /// picks a worker and calls OneToOneUniQueue::pop() using its queue
    template <class Value> bool pop(int &workerId, Value &value);

    /// calls OneToOneUniQueue::push() using the given worker queue
    template <class Value> bool push(const int workerId, const Value &value);

//private: XXX: make private by moving pop/push debugging into pop/push
    int theLastPopWorker; ///< the ID of the last worker we tried to pop() from
    Vector<OneToOneBiQueue *> biQueues; ///< worker queues indexed by worker ID
    const int theWorkerCount; ///< the total number of workers

    Ipc::Mem::Segment shm; ///< shared memory segment to store the reader
    QueueReader *reader; ///< the state of the code popping from all biQueues

    enum { WorkerIdOffset = 1 }; ///< worker ID offset, always 1 for now
};


// OneToOneUniQueue

template <class Value>
bool
OneToOneUniQueue::pop(Value &value)
{
    if (sizeof(value) > shared->theMaxItemSize)
        throw ItemTooLarge();

    // A writer might push between the empty test and block() below, so we do
    // not return false right after calling block(), but test again.
    if (empty()) {
        reader().block();
        // A writer might push between the empty test and block() below,
        // so we must test again as such a writer will not signal us.
        if (empty())
            return false;
    }

    reader().unblock();
    const unsigned int pos =
        (shared->theOut++ % shared->theCapacity) * shared->theMaxItemSize;
    memcpy(&value, shared->theBuffer + pos, sizeof(value));
    --shared->theSize;

    return true;
}

template <class Value>
bool
OneToOneUniQueue::push(const Value &value)
{
    if (sizeof(value) > shared->theMaxItemSize)
        throw ItemTooLarge();

    if (full())
        throw Full();

    const bool wasEmpty = empty();
    const unsigned int pos =
        shared->theIn++ % shared->theCapacity * shared->theMaxItemSize;
    memcpy(shared->theBuffer + pos, &value, sizeof(value));
    ++shared->theSize;

    return wasEmpty && reader().raiseSignal();
}


// FewToOneBiQueue

template <class Value>
bool
FewToOneBiQueue::pop(int &workerId, Value &value)
{
    // iterate all workers, starting after the one we visited last
    for (int i = 0; i < theWorkerCount; ++i) {
        theLastPopWorker = (theLastPopWorker + 1) % theWorkerCount;
        if (biQueues[theLastPopWorker]->pop(value)) {
            workerId = theLastPopWorker + WorkerIdOffset;
            return true;
        }
    }
    return false; // no worker had anything to pop
}

template <class Value>
bool
FewToOneBiQueue::push(const int workerId, const Value &value)
{
    assert(validWorkerId(workerId));
    return biQueues[workerId - WorkerIdOffset]->push(value);
}

#endif // SQUID_IPC_QUEUE_H
