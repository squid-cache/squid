/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "ipc/Queue.h"


static String
QueueId(String id, const int idx)
{
    id.append("__");
    id.append(xitoa(idx));
    return id;
}


// OneToOneUniQueue

OneToOneUniQueue::OneToOneUniQueue(const String &id, const unsigned int maxItemSize, const int capacity):
    shm(id.termedBuf())
{
    shm.create(Items2Bytes(maxItemSize, capacity));
    assert(shm.mem());
    shared = new (shm.mem()) Shared(maxItemSize, capacity);
}

OneToOneUniQueue::OneToOneUniQueue(const String &id): shm(id.termedBuf())
{
    shm.open();
    shared = reinterpret_cast<Shared *>(shm.mem());
    assert(shared);
}

int
OneToOneUniQueue::Bytes2Items(const unsigned int maxItemSize, int size)
{
    assert(maxItemSize > 0);
    size -= sizeof(Shared);
    return size >= 0 ? size / maxItemSize : 0;
}

int
OneToOneUniQueue::Items2Bytes(const unsigned int maxItemSize, const int size)
{
    assert(size >= 0);
    return sizeof(Shared) + maxItemSize * size;
}

OneToOneUniQueue::Shared::Shared(const unsigned int aMaxItemSize, const int aCapacity):
    theIn(0), theOut(0), theSize(0), theMaxItemSize(aMaxItemSize),
    theCapacity(aCapacity)
{
}


// OneToOneBiQueue

OneToOneBiQueue::OneToOneBiQueue(const String &id, const unsigned int maxItemSize, const int capacity):
    popQueue(new OneToOneUniQueue(QueueId(id, 1), maxItemSize, capacity)),
    pushQueue(new OneToOneUniQueue(QueueId(id, 2), maxItemSize, capacity))
{
}

OneToOneBiQueue::OneToOneBiQueue(const String &id):
    popQueue(new OneToOneUniQueue(QueueId(id, 2))),
    pushQueue(new OneToOneUniQueue(QueueId(id, 1)))
{
}


// FewToOneBiQueue

FewToOneBiQueue::FewToOneBiQueue(const String &id, const int aWorkerCount, const unsigned int maxItemSize, const int capacity):
    theLastPopWorkerId(-1), theWorkerCount(aWorkerCount)
{
    assert(theWorkerCount >= 0);
    biQueues.reserve(theWorkerCount);
    for (int i = 0; i < theWorkerCount; ++i) {
        OneToOneBiQueue *const biQueue =
            new OneToOneBiQueue(QueueId(id, i), maxItemSize, capacity);
        biQueues.push_back(biQueue);
    }
}

OneToOneBiQueue *
FewToOneBiQueue::Attach(const String &id, const int workerId)
{
    return new OneToOneBiQueue(QueueId(id, workerId));
}

FewToOneBiQueue::~FewToOneBiQueue()
{
    for (int i = 0; i < theWorkerCount; ++i)
        delete biQueues[i];
}

bool FewToOneBiQueue::validWorkerId(const int workerId) const
{
    return 0 <= workerId && workerId < theWorkerCount;
}
