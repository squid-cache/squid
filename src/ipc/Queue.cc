/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "Debug.h"
#include "globals.h"
#include "ipc/Queue.h"

/// constructs shared segment ID from parent queue ID and child queue index
static String
QueueId(String id, const int idx)
{
    id.append("__");
    id.append(xitoa(idx));
    return id;
}

/// constructs QueueReader ID from parent queue ID
static String
ReaderId(String id)
{
    id.append("__readers");
    return id;
}


/* QueueReader */

InstanceIdDefinitions(Ipc::QueueReader, "ipcQR");

Ipc::QueueReader::QueueReader(): popBlocked(1), popSignal(0)
{
    debugs(54, 7, HERE << "constructed " << id);
}

/* QueueReaders */

Ipc::QueueReaders::QueueReaders(const int aCapacity): theCapacity(aCapacity)
{
    Must(theCapacity > 0);
    new (theReaders) QueueReader[theCapacity];
}

size_t
Ipc::QueueReaders::sharedMemorySize() const
{
    return SharedMemorySize(theCapacity);
}

size_t
Ipc::QueueReaders::SharedMemorySize(const int capacity)
{
    return sizeof(QueueReaders) + sizeof(QueueReader) * capacity;
}


// OneToOneUniQueue

Ipc::OneToOneUniQueue::Owner *
Ipc::OneToOneUniQueue::Init(const String &id, const unsigned int maxItemSize, const int capacity)
{
    Must(maxItemSize > 0);
    Must(capacity > 0);
    return shm_new(Shared)(id.termedBuf(), maxItemSize, capacity);
}

Ipc::OneToOneUniQueue::OneToOneUniQueue(const String &id):
    shared(shm_old(Shared)(id.termedBuf())), reader_(NULL)
{
}

void
Ipc::OneToOneUniQueue::reader(QueueReader *aReader)
{
    Must(!reader_ && aReader);
    reader_ = aReader;
}

int
Ipc::OneToOneUniQueue::Bytes2Items(const unsigned int maxItemSize, int size)
{
    assert(maxItemSize > 0);
    size -= sizeof(Shared);
    return size >= 0 ? size / maxItemSize : 0;
}

int
Ipc::OneToOneUniQueue::Items2Bytes(const unsigned int maxItemSize, const int size)
{
    assert(size >= 0);
    return sizeof(Shared) + maxItemSize * size;
}

Ipc::QueueReader &
Ipc::OneToOneUniQueue::reader()
{
    Must(reader_);
    return *reader_;
}

Ipc::OneToOneUniQueue::Shared::Shared(const unsigned int aMaxItemSize, const int aCapacity):
    theIn(0), theOut(0), theSize(0), theMaxItemSize(aMaxItemSize),
    theCapacity(aCapacity)
{
}

size_t
Ipc::OneToOneUniQueue::Shared::sharedMemorySize() const
{
    return SharedMemorySize(theMaxItemSize, theCapacity);
}

size_t
Ipc::OneToOneUniQueue::Shared::SharedMemorySize(const unsigned int maxItemSize, const int capacity)
{
    return Items2Bytes(maxItemSize, capacity);
}


// OneToOneBiQueue

Ipc::OneToOneBiQueue::Owner *
Ipc::OneToOneBiQueue::Init(const String &id, const unsigned int maxItemSize, const int capacity)
{
    UniQueueOwner owner1(OneToOneUniQueue::Init(QueueId(id, Side1), maxItemSize, capacity));
    UniQueueOwner owner2(OneToOneUniQueue::Init(QueueId(id, Side2), maxItemSize, capacity));
    Owner *const owner = new Owner;
    owner->first = owner1;
    owner->second = owner2;
    return owner;
}

Ipc::OneToOneBiQueue::OneToOneBiQueue(const String &id, const Side side)
{
    OneToOneUniQueue *const queue1 = new OneToOneUniQueue(QueueId(id, Side1));
    OneToOneUniQueue *const queue2 = new OneToOneUniQueue(QueueId(id, Side2));
    switch (side) {
    case Side1:
        popQueue.reset(queue1);
        pushQueue.reset(queue2);
        break;
    case Side2:
        popQueue.reset(queue2);
        pushQueue.reset(queue1);
        break;
    default:
        Must(false);
    }
}

void
Ipc::OneToOneBiQueue::readers(QueueReader *r1, QueueReader *r2)
{
    popQueue->reader(r1);
    pushQueue->reader(r2);
}

void
Ipc::OneToOneBiQueue::clearReaderSignal()
{
    debugs(54, 7, HERE << "reader: " << &popQueue->reader());
    popQueue->reader().clearSignal();
}


// FewToOneBiQueue

Ipc::FewToOneBiQueue::Owner *
Ipc::FewToOneBiQueue::Init(const String &id, const int workerCount, const unsigned int maxItemSize, const int capacity)
{
    return new Owner(id, workerCount, maxItemSize, capacity);
}

Ipc::FewToOneBiQueue::FewToOneBiQueue(const String &id):
    theLastPopWorker(0),
    readers(shm_old(QueueReaders)(ReaderId(id).termedBuf())),
    reader(readers->theReaders)
{
    Must(readers->theCapacity > 1);

    debugs(54, 7, HERE << "disker " << id << " reader: " << reader->id);

    biQueues.reserve(workerCount());
    for (int i = 0; i < workerCount(); ++i) {
        OneToOneBiQueue *const biQueue = new OneToOneBiQueue(QueueId(id, i + WorkerIdOffset), OneToOneBiQueue::Side1);
        QueueReader *const remoteReader = readers->theReaders + i + 1;
        biQueue->readers(reader, remoteReader);
        biQueues.push_back(biQueue);
    }
}

Ipc::OneToOneBiQueue *
Ipc::FewToOneBiQueue::Attach(const String &id, const int workerId)
{
    Mem::Pointer<QueueReaders> readers = shm_old(QueueReaders)(ReaderId(id).termedBuf());
    Must(workerId >= WorkerIdOffset);
    Must(workerId < readers->theCapacity - 1 + WorkerIdOffset);
    QueueReader *const remoteReader = readers->theReaders;
    debugs(54, 7, HERE << "disker " << id << " reader: " << remoteReader->id);
    QueueReader *const localReader =
        readers->theReaders + workerId - WorkerIdOffset + 1;
    debugs(54, 7, HERE << "local " << id << " reader: " << localReader->id);

    OneToOneBiQueue *const biQueue =
        new OneToOneBiQueue(QueueId(id, workerId), OneToOneBiQueue::Side2);
    biQueue->readers(localReader, remoteReader);

    // XXX: remove this leak. By refcounting Ipc::Mem::Segments? By creating a global FewToOneBiQueue for each worker?
    const Mem::Pointer<QueueReaders> *const leakingReaders = new Mem::Pointer<QueueReaders>(readers);
    Must(leakingReaders); // silence unused variable warning

    return biQueue;
}

Ipc::FewToOneBiQueue::~FewToOneBiQueue()
{
    for (int i = 0; i < workerCount(); ++i)
        delete biQueues[i];
}

bool
Ipc::FewToOneBiQueue::validWorkerId(const int workerId) const
{
    return WorkerIdOffset <= workerId &&
        workerId < WorkerIdOffset + workerCount();
}

void
Ipc::FewToOneBiQueue::clearReaderSignal(int workerId)
{
    debugs(54, 7, HERE << "reader: " << reader->id);

    assert(validWorkerId(workerId));
    reader->clearSignal();

    // we got a hint; we could reposition iteration to try popping from the
    // workerId queue first; but it does not seem to help much and might
    // introduce some bias so we do not do that for now:
    // theLastPopWorker = (workerId + workerCount() - 1) % workerCount();
}

Ipc::FewToOneBiQueue::Owner::Owner(const String &id, const int workerCount, const unsigned int maxItemSize, const int capacity):
    readersOwner(shm_new(QueueReaders)(ReaderId(id).termedBuf(), workerCount + 1))
{
    biQueueOwners.reserve(workerCount);
    for (int i = 0; i < workerCount; ++i) {
        OneToOneBiQueue::Owner *const queueOwner = OneToOneBiQueue::Init(QueueId(id, i + WorkerIdOffset), maxItemSize, capacity);
        biQueueOwners.push_back(queueOwner);
    }
}

Ipc::FewToOneBiQueue::Owner::~Owner()
{
    for (size_t i = 0; i < biQueueOwners.size(); ++i)
        delete biQueueOwners[i];
    delete readersOwner;
}
