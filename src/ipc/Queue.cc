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

InstanceIdDefinitions(QueueReader, "ipcQR");

QueueReader::QueueReader(): popBlocked(1), popSignal(0)
{
    debugs(54, 7, HERE << "constructed " << id);
}


// OneToOneUniQueue

OneToOneUniQueue::OneToOneUniQueue(const String &id, const unsigned int maxItemSize, const int capacity):
    shm(id.termedBuf()), reader_(NULL)
{
    const int sharedSize = Items2Bytes(maxItemSize, capacity);
    shm.create(sharedSize);
    shared = new (shm.reserve(sharedSize)) Shared(maxItemSize, capacity);
}

OneToOneUniQueue::OneToOneUniQueue(const String &id): shm(id.termedBuf()),
    reader_(NULL)
{
    shm.open();
    shared = reinterpret_cast<Shared *>(shm.mem());
    assert(shared);
    const int sharedSize =
        Items2Bytes(shared->theMaxItemSize, shared->theCapacity);
    assert(shared == reinterpret_cast<Shared *>(shm.reserve(sharedSize)));
}

void
OneToOneUniQueue::reader(QueueReader *aReader)
{
    Must(!reader_ && aReader);
    reader_ = aReader;
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

QueueReader &
OneToOneUniQueue::reader()
{
    Must(reader_);
    return *reader_;
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

void
OneToOneBiQueue::readers(QueueReader *r1, QueueReader *r2)
{
    popQueue->reader(r1);
    pushQueue->reader(r2);
}

void
OneToOneBiQueue::clearReaderSignal()
{
    debugs(54, 7, HERE << "reader: " << &popQueue->reader());
    popQueue->reader().clearSignal();
}


// FewToOneBiQueue

FewToOneBiQueue::FewToOneBiQueue(const String &id, const int aWorkerCount, const unsigned int maxItemSize, const int capacity):
    theLastPopWorker(0), theWorkerCount(aWorkerCount),
    shm(ReaderId(id).termedBuf()),
    reader(NULL)
{
    // create a new segment for the local and remote queue readers
    // TODO: all our queues and readers should use a single segment
    shm.create((theWorkerCount+1)*sizeof(QueueReader));
    reader = new (shm.reserve(sizeof(QueueReader))) QueueReader;
    debugs(54, 7, HERE << "disker " << id << " reader: " << reader->id);

    assert(theWorkerCount >= 0);
    biQueues.reserve(theWorkerCount);
    for (int i = 0; i < theWorkerCount; ++i) {
        OneToOneBiQueue *const biQueue =
            new OneToOneBiQueue(QueueId(id, i + WorkerIdOffset), maxItemSize, capacity);
        QueueReader *remoteReader =
            new (shm.reserve(sizeof(QueueReader))) QueueReader;
        biQueue->readers(reader, remoteReader);
        biQueues.push_back(biQueue);
    }
}

OneToOneBiQueue *
FewToOneBiQueue::Attach(const String &id, const int workerId)
{
    // XXX: remove this leak. By refcounting Ipc::Mem::Segments? By creating a global FewToOneBiQueue for each worker?
    Ipc::Mem::Segment *shmPtr = new Ipc::Mem::Segment(ReaderId(id).termedBuf());

    Ipc::Mem::Segment &shm = *shmPtr;
    shm.open();
    assert(shm.size() >= static_cast<off_t>((1 + workerId+1 - WorkerIdOffset)*sizeof(QueueReader)));
    QueueReader *readers = reinterpret_cast<QueueReader*>(shm.mem());
    QueueReader *remoteReader = &readers[0];
    debugs(54, 7, HERE << "disker " << id << " reader: " << remoteReader->id);
    QueueReader *localReader = &readers[workerId+1 - WorkerIdOffset];
    debugs(54, 7, HERE << "local " << id << " reader: " << localReader->id);

    OneToOneBiQueue *const biQueue =
        new OneToOneBiQueue(QueueId(id, workerId));
    biQueue->readers(localReader, remoteReader);
    return biQueue;
}

FewToOneBiQueue::~FewToOneBiQueue()
{
    for (int i = 0; i < theWorkerCount; ++i)
        delete biQueues[i];
}

bool FewToOneBiQueue::validWorkerId(const int workerId) const
{
    return WorkerIdOffset <= workerId &&
        workerId < WorkerIdOffset + theWorkerCount;
}

void
FewToOneBiQueue::clearReaderSignal(int workerId)
{
    debugs(54, 7, HERE << "reader: " << reader->id);

    assert(validWorkerId(workerId));
    reader->clearSignal();

    // we got a hint; we could reposition iteration to try popping from the
    // workerId queue first; but it does not seem to help much and might
    // introduce some bias so we do not do that for now:
    // theLastPopWorker = (workerId + theWorkerCount - 1) % theWorkerCount;
}
