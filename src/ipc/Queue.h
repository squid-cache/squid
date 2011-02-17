/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_QUEUE_H
#define SQUID_IPC_QUEUE_H

#include "Array.h"
#include "ipc/AtomicWord.h"
#include "ipc/SharedMemory.h"
#include "SquidString.h"
#include "util.h"

/// Lockless fixed-capacity queue for a single writer and a single
/// reader. Does not manage shared memory segment.
template <class Value>
class OneToOneUniQueue {
public:
    OneToOneUniQueue(const int aCapacity);

    int size() const { return theSize; }
    int capacity() const { return theCapacity; }

    bool empty() const { return !theSize; }
    bool full() const { return theSize == theCapacity; }

    bool pop(Value &value); ///< returns false iff the queue is empty
    bool push(const Value &value); ///< returns false iff the queue is full

    static int Bytes2Items(int size);
    static int Items2Bytes(const int size);

private:
    unsigned int theIn; ///< input index, used only in push()
    unsigned int theOut; ///< output index, used only in pop()

    AtomicWord theSize; ///< number of items in the queue
    const int theCapacity; ///< maximum number of items, i.e. theBuffer size
    Value theBuffer[];
};

/// Lockless fixed-capacity bidirectional queue for two processes.
/// Manages shared memory segment.
template <class Value>
class OneToOneBiQueue {
public:
    typedef OneToOneUniQueue<Value> UniQueue;

    /// Create a new shared queue.
    OneToOneBiQueue(const char *const id, const int aCapacity);
    OneToOneBiQueue(const char *const id); ///< Attach to existing shared queue.

    int pushedSize() const { return pushQueue->size(); }

    bool pop(Value &value) { return popQueue->pop(value); }
    bool push(const Value &value) { return pushQueue->push(value); }

private:
    SharedMemory shm; ///< shared memory segment
    UniQueue *popQueue; ///< queue to pop from for this process
    UniQueue *pushQueue; ///< queue to push to for this process
};

/**
 * Lockless fixed-capacity bidirectional queue for a limited number
 * pricesses. Implements a star topology: Many worker processes
 * communicate with the one central process. The central process uses
 * FewToOneBiQueue object, while workers use OneToOneBiQueue objects
 * created with the Attach() method. Each worker has a unique integer ID
 * in [0, workerCount) range.
 */
template <class Value>
class FewToOneBiQueue {
public:
    typedef OneToOneBiQueue<Value> BiQueue;

    FewToOneBiQueue(const char *const id, const int aWorkerCount, const int aCapacity);
    static BiQueue *Attach(const char *const id, const int workerId);
    ~FewToOneBiQueue();

    bool validWorkerId(const int workerId) const;
    int workerCount() const { return theWorkerCount; }
    int pushedSize(const int workerId) const;

    bool pop(int &workerId, Value &value); ///< returns false iff the queue is empty
    bool push(const int workerId, const Value &value); ///< returns false iff the queue is full

private:
    static String BiQueueId(String id, const int workerId);

    int theLastPopWorkerId; ///< the last worker ID we pop()ed from
    Vector<BiQueue *> biQueues; ///< worker queues
    const int theWorkerCount; ///< number of worker processes
    const int theCapacity; ///< per-worker capacity
};


// OneToOneUniQueue

template <class Value>
OneToOneUniQueue<Value>::OneToOneUniQueue(const int aCapacity):
    theIn(0), theOut(0), theSize(0), theCapacity(aCapacity)
{
    assert(theCapacity > 0);
}

template <class Value>
bool
OneToOneUniQueue<Value>::pop(Value &value)
{
    if (empty())
        return false;

    const unsigned int pos = theOut++ % theCapacity;
    value = theBuffer[pos];
    --theSize;
    return true;
}

template <class Value>
bool
OneToOneUniQueue<Value>::push(const Value &value)
{
    if (full())
        return false;

    const unsigned int pos = theIn++ % theCapacity;
    theBuffer[pos] = value;
    ++theSize;
    return true;
}

template <class Value>
int
OneToOneUniQueue<Value>::Bytes2Items(int size)
{
    assert(size >= 0);
    size -= sizeof(OneToOneUniQueue);
    return size >= 0 ? size / sizeof(Value) : 0;
}

template <class Value>
int
OneToOneUniQueue<Value>::Items2Bytes(const int size)
{
    assert(size >= 0);
    return sizeof(OneToOneUniQueue) + sizeof(Value) * size;
}


// OneToOneBiQueue

template <class Value>
OneToOneBiQueue<Value>::OneToOneBiQueue(const char *const id, const int capacity) :
    shm(id)
{
    const int uniSize = UniQueue::Items2Bytes(capacity);
    shm.create(uniSize * 2);
    char *const mem = reinterpret_cast<char *>(shm.mem());
    assert(mem);
    popQueue = new (mem) UniQueue(capacity);
    pushQueue = new (mem + uniSize) UniQueue(capacity);
}

template <class Value>
OneToOneBiQueue<Value>::OneToOneBiQueue(const char *const id) :
    shm(id)
{
    shm.open();
    char *const mem = reinterpret_cast<char *>(shm.mem());
    assert(mem);
    pushQueue = reinterpret_cast<UniQueue *>(mem);
    const int uniSize = pushQueue->Items2Bytes(pushQueue->capacity());
    popQueue = reinterpret_cast<UniQueue *>(mem + uniSize);
}

// FewToOneBiQueue

template <class Value>
FewToOneBiQueue<Value>::FewToOneBiQueue(const char *const id, const int aWorkerCount, const int aCapacity):
    theLastPopWorkerId(-1), theWorkerCount(aWorkerCount),
    theCapacity(aCapacity)
{
    biQueues.reserve(theWorkerCount);
    for (int i = 0; i < theWorkerCount; ++i) {
        const String biQueueId = BiQueueId(id, i);
        biQueues.push_back(new BiQueue(biQueueId.termedBuf(), theCapacity));
    }
}

template <class Value>
typename FewToOneBiQueue<Value>::BiQueue *
FewToOneBiQueue<Value>::Attach(const char *const id, const int workerId)
{
    return new BiQueue(BiQueueId(id, workerId).termedBuf());
}

template <class Value>
FewToOneBiQueue<Value>::~FewToOneBiQueue()
{
    for (int i = 0; i < theWorkerCount; ++i)
        delete biQueues[i];
}

template <class Value>
bool FewToOneBiQueue<Value>::validWorkerId(const int workerId) const
{
    return 0 <= workerId && workerId < theWorkerCount;
}

template <class Value>
int FewToOneBiQueue<Value>::pushedSize(const int workerId) const
{
    assert(validWorkerId(workerId));
    return biQueues[workerId]->pushedSize();
}

template <class Value>
bool
FewToOneBiQueue<Value>::pop(int &workerId, Value &value)
{
    ++theLastPopWorkerId;
    for (int i = 0; i < theWorkerCount; ++i) {
        theLastPopWorkerId = (theLastPopWorkerId + 1) % theWorkerCount;
        if (biQueues[theLastPopWorkerId]->pop(value)) {
            workerId = theLastPopWorkerId;
            return true;
        }
    }
    return false;
}

template <class Value>
bool
FewToOneBiQueue<Value>::push(const int workerId, const Value &value)
{
    assert(validWorkerId(workerId));
    return biQueues[workerId]->push(value);
}

template <class Value>
String
FewToOneBiQueue<Value>::BiQueueId(String id, const int workerId)
{
    id.append("__");
    id.append(xitoa(workerId));
    return id;
}

#endif // SQUID_IPC_QUEUE_H
