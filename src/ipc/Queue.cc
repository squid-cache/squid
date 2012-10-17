/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "squid.h"
#include "base/TextException.h"
#include "Debug.h"
#include "globals.h"
#include "ipc/Queue.h"

/// constructs Metadata ID from parent queue ID
static String
MetadataId(String id)
{
    id.append("__metadata");
    return id;
}

/// constructs one-to-one queues ID from parent queue ID
static String
QueuesId(String id)
{
    id.append("__queues");
    return id;
}

/// constructs QueueReaders ID from parent queue ID
static String
ReadersId(String id)
{
    id.append("__readers");
    return id;
}

/* QueueReader */

InstanceIdDefinitions(Ipc::QueueReader, "ipcQR");

Ipc::QueueReader::QueueReader(): popBlocked(1), popSignal(0),
        rateLimit(0), balance(0)
{
    debugs(54, 7, HERE << "constructed " << id);
}

/* QueueReaders */

Ipc::QueueReaders::QueueReaders(const int aCapacity): theCapacity(aCapacity),
        theReaders(theCapacity)
{
    Must(theCapacity > 0);
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

Ipc::OneToOneUniQueue::OneToOneUniQueue(const unsigned int aMaxItemSize, const int aCapacity):
        theIn(0), theOut(0), theSize(0), theMaxItemSize(aMaxItemSize),
        theCapacity(aCapacity)
{
    Must(theMaxItemSize > 0);
    Must(theCapacity > 0);
}

int
Ipc::OneToOneUniQueue::Bytes2Items(const unsigned int maxItemSize, int size)
{
    assert(maxItemSize > 0);
    size -= sizeof(OneToOneUniQueue);
    return size >= 0 ? size / maxItemSize : 0;
}

int
Ipc::OneToOneUniQueue::Items2Bytes(const unsigned int maxItemSize, const int size)
{
    assert(size >= 0);
    return sizeof(OneToOneUniQueue) + maxItemSize * size;
}

/* OneToOneUniQueues */

Ipc::OneToOneUniQueues::OneToOneUniQueues(const int aCapacity, const unsigned int maxItemSize, const int queueCapacity): theCapacity(aCapacity)
{
    Must(theCapacity > 0);
    for (int i = 0; i < theCapacity; ++i)
        new (&(*this)[i]) OneToOneUniQueue(maxItemSize, queueCapacity);
}

size_t
Ipc::OneToOneUniQueues::sharedMemorySize() const
{
    return sizeof(*this) + theCapacity * front().sharedMemorySize();
}

size_t
Ipc::OneToOneUniQueues::SharedMemorySize(const int capacity, const unsigned int maxItemSize, const int queueCapacity)
{
    const int queueSize =
        OneToOneUniQueue::Items2Bytes(maxItemSize, queueCapacity);
    return sizeof(OneToOneUniQueues) + queueSize * capacity;
}

const Ipc::OneToOneUniQueue &
Ipc::OneToOneUniQueues::operator [](const int index) const
{
    Must(0 <= index && index < theCapacity);
    const size_t queueSize = index ? front().sharedMemorySize() : 0;
    const char *const queue =
        reinterpret_cast<const char *>(this) + sizeof(*this) + index * queueSize;
    return *reinterpret_cast<const OneToOneUniQueue *>(queue);
}

// FewToFewBiQueue

Ipc::FewToFewBiQueue::Owner *
Ipc::FewToFewBiQueue::Init(const String &id, const int groupASize, const int groupAIdOffset, const int groupBSize, const int groupBIdOffset, const unsigned int maxItemSize, const int capacity)
{
    return new Owner(id, groupASize, groupAIdOffset, groupBSize, groupBIdOffset, maxItemSize, capacity);
}

Ipc::FewToFewBiQueue::FewToFewBiQueue(const String &id, const Group aLocalGroup, const int aLocalProcessId):
        metadata(shm_old(Metadata)(MetadataId(id).termedBuf())),
        queues(shm_old(OneToOneUniQueues)(QueuesId(id).termedBuf())),
        readers(shm_old(QueueReaders)(ReadersId(id).termedBuf())),
        theLocalGroup(aLocalGroup), theLocalProcessId(aLocalProcessId),
        theLastPopProcessId(readers->theCapacity)
{
    Must(queues->theCapacity == metadata->theGroupASize * metadata->theGroupBSize * 2);
    Must(readers->theCapacity == metadata->theGroupASize + metadata->theGroupBSize);

    const QueueReader &localReader = reader(theLocalGroup, theLocalProcessId);
    debugs(54, 7, HERE << "queue " << id << " reader: " << localReader.id);
}

int
Ipc::FewToFewBiQueue::MaxItemsCount(const int groupASize, const int groupBSize, const int capacity)
{
    return capacity * groupASize * groupBSize * 2;
}

bool
Ipc::FewToFewBiQueue::validProcessId(const Group group, const int processId) const
{
    switch (group) {
    case groupA:
        return metadata->theGroupAIdOffset <= processId &&
               processId < metadata->theGroupAIdOffset + metadata->theGroupASize;
    case groupB:
        return metadata->theGroupBIdOffset <= processId &&
               processId < metadata->theGroupBIdOffset + metadata->theGroupBSize;
    }
    return false;
}

int
Ipc::FewToFewBiQueue::oneToOneQueueIndex(const Group fromGroup, const int fromProcessId, const Group toGroup, const int toProcessId) const
{
    Must(fromGroup != toGroup);
    assert(validProcessId(fromGroup, fromProcessId));
    assert(validProcessId(toGroup, toProcessId));
    int index1;
    int index2;
    int offset;
    if (fromGroup == groupA) {
        index1 = fromProcessId - metadata->theGroupAIdOffset;
        index2 = toProcessId - metadata->theGroupBIdOffset;
        offset = 0;
    } else {
        index1 = toProcessId - metadata->theGroupAIdOffset;
        index2 = fromProcessId - metadata->theGroupBIdOffset;
        offset = metadata->theGroupASize * metadata->theGroupBSize;
    }
    const int index = offset + index1 * metadata->theGroupBSize + index2;
    return index;
}

Ipc::OneToOneUniQueue &
Ipc::FewToFewBiQueue::oneToOneQueue(const Group fromGroup, const int fromProcessId, const Group toGroup, const int toProcessId)
{
    return (*queues)[oneToOneQueueIndex(fromGroup, fromProcessId, toGroup, toProcessId)];
}

const Ipc::OneToOneUniQueue &
Ipc::FewToFewBiQueue::oneToOneQueue(const Group fromGroup, const int fromProcessId, const Group toGroup, const int toProcessId) const
{
    return (*queues)[oneToOneQueueIndex(fromGroup, fromProcessId, toGroup, toProcessId)];
}

/// incoming queue from a given remote process
const Ipc::OneToOneUniQueue &
Ipc::FewToFewBiQueue::inQueue(const int remoteProcessId) const
{
    return oneToOneQueue(remoteGroup(), remoteProcessId,
                         theLocalGroup, theLocalProcessId);
}

/// outgoing queue to a given remote process
const Ipc::OneToOneUniQueue &
Ipc::FewToFewBiQueue::outQueue(const int remoteProcessId) const
{
    return oneToOneQueue(theLocalGroup, theLocalProcessId,
                         remoteGroup(), remoteProcessId);
}

int
Ipc::FewToFewBiQueue::readerIndex(const Group group, const int processId) const
{
    Must(validProcessId(group, processId));
    return group == groupA ?
           processId - metadata->theGroupAIdOffset :
           metadata->theGroupASize + processId - metadata->theGroupBIdOffset;
}

Ipc::QueueReader &
Ipc::FewToFewBiQueue::reader(const Group group, const int processId)
{
    return readers->theReaders[readerIndex(group, processId)];
}

const Ipc::QueueReader &
Ipc::FewToFewBiQueue::reader(const Group group, const int processId) const
{
    return readers->theReaders[readerIndex(group, processId)];
}

void
Ipc::FewToFewBiQueue::clearReaderSignal(const int remoteProcessId)
{
    QueueReader &localReader = reader(theLocalGroup, theLocalProcessId);
    debugs(54, 7, HERE << "reader: " << localReader.id);

    Must(validProcessId(remoteGroup(), remoteProcessId));
    localReader.clearSignal();

    // we got a hint; we could reposition iteration to try popping from the
    // remoteProcessId queue first; but it does not seem to help much and might
    // introduce some bias so we do not do that for now:
    // theLastPopProcessId = remoteProcessId;
}

Ipc::QueueReader::Balance &
Ipc::FewToFewBiQueue::localBalance()
{
    QueueReader &r = reader(theLocalGroup, theLocalProcessId);
    return r.balance;
}

const Ipc::QueueReader::Balance &
Ipc::FewToFewBiQueue::balance(const int remoteProcessId) const
{
    const QueueReader &r = reader(remoteGroup(), remoteProcessId);
    return r.balance;
}

Ipc::QueueReader::Rate &
Ipc::FewToFewBiQueue::localRateLimit()
{
    QueueReader &r = reader(theLocalGroup, theLocalProcessId);
    return r.rateLimit;
}

const Ipc::QueueReader::Rate &
Ipc::FewToFewBiQueue::rateLimit(const int remoteProcessId) const
{
    const QueueReader &r = reader(remoteGroup(), remoteProcessId);
    return r.rateLimit;
}

Ipc::FewToFewBiQueue::Metadata::Metadata(const int aGroupASize, const int aGroupAIdOffset, const int aGroupBSize, const int aGroupBIdOffset):
        theGroupASize(aGroupASize), theGroupAIdOffset(aGroupAIdOffset),
        theGroupBSize(aGroupBSize), theGroupBIdOffset(aGroupBIdOffset)
{
    Must(theGroupASize > 0);
    Must(theGroupBSize > 0);
}

Ipc::FewToFewBiQueue::Owner::Owner(const String &id, const int groupASize, const int groupAIdOffset, const int groupBSize, const int groupBIdOffset, const unsigned int maxItemSize, const int capacity):
        metadataOwner(shm_new(Metadata)(MetadataId(id).termedBuf(), groupASize, groupAIdOffset, groupBSize, groupBIdOffset)),
        queuesOwner(shm_new(OneToOneUniQueues)(QueuesId(id).termedBuf(), groupASize*groupBSize*2, maxItemSize, capacity)),
        readersOwner(shm_new(QueueReaders)(ReadersId(id).termedBuf(), groupASize+groupBSize))
{
}

Ipc::FewToFewBiQueue::Owner::~Owner()
{
    delete metadataOwner;
    delete queuesOwner;
    delete readersOwner;
}
