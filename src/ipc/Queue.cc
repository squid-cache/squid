/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/TextException.h"
#include "debug/Stream.h"
#include "globals.h"
#include "ipc/Queue.h"

#include <limits>

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

Ipc::QueueReader::QueueReader(): popBlocked(false), popSignal(false),
    rateLimit(0), balance(0)
{
    debugs(54, 7, "constructed " << id);
}

/* QueueReaders */

size_t
Ipc::QueueReaders::SharedMemorySize(const size_t capacity)
{
    return sizeof(QueueReaders) + sizeof(QueueReader) * capacity;
}

// OneToOneUniQueue

Ipc::OneToOneUniQueue::OneToOneUniQueue(const size_t aMaxItemSize, const size_t aCapacity):
    theSize(0),
    theMaxItemSize(aMaxItemSize),
    theCapacity(aCapacity)
{
    assert(theMaxItemSize > 0);
    assert(theCapacity > 0);
}

size_t
Ipc::OneToOneUniQueue::Items2Bytes(const size_t maxItemSize, const size_t size)
{
    return sizeof(OneToOneUniQueue) + maxItemSize * size;
}

/// start state reporting (by reporting queue parameters)
/// The labels reflect whether the caller owns theIn or theOut data member and,
/// hence, cannot report the other value reliably.
void
Ipc::OneToOneUniQueue::statOpen(std::ostream &os, const char *inLabel, const char *outLabel, const size_t count) const
{
    os << "{ size: " << count <<
       ", capacity: " << theCapacity <<
       ", " << inLabel << ": " << theIn <<
       ", " << outLabel << ": " << theOut;
}

/// end state reporting started by statOpen()
void
Ipc::OneToOneUniQueue::statClose(std::ostream &os) const
{
    os << "}\n";
}

/* OneToOneUniQueues */

Ipc::OneToOneUniQueues::OneToOneUniQueues(const size_t aCapacity, const size_t maxItemSize, const size_t queueCapacity) :
    theCapacity(aCapacity)
{
    Must(theCapacity > 0);
    for (size_t i = 0; i < theCapacity; ++i)
        new (&(*this)[i]) OneToOneUniQueue(maxItemSize, queueCapacity);
}

size_t
Ipc::OneToOneUniQueues::sharedMemorySize() const
{
    // XXX: wrong when front() queue size != constructor maxItemSize
    return sizeof(*this) + theCapacity * front().sharedMemorySize();
}

size_t
Ipc::OneToOneUniQueues::SharedMemorySize(const size_t capacity, const size_t maxItemSize, const size_t queueCapacity)
{
    const auto queueSize =
        OneToOneUniQueue::Items2Bytes(maxItemSize, queueCapacity);
    return sizeof(OneToOneUniQueues) + queueSize * capacity;
}

const Ipc::OneToOneUniQueue &
Ipc::OneToOneUniQueues::operator [](const size_t index) const
{
    Must(index < theCapacity);
    const size_t queueSize = index ? front().sharedMemorySize() : 0;
    const auto queue = reinterpret_cast<const char *>(this) + sizeof(*this) + index * queueSize;
    return *reinterpret_cast<const OneToOneUniQueue *>(queue);
}

// BaseMultiQueue

Ipc::BaseMultiQueue::BaseMultiQueue(const int aLocalProcessId):
    theLocalProcessId(aLocalProcessId),
    theLastPopProcessId(std::numeric_limits<int>::max() - 1)
{
}

void
Ipc::BaseMultiQueue::clearReaderSignal(const int /*remoteProcessId*/)
{
    // Unused remoteProcessId may be useful for at least two optimizations:
    // * TODO: After QueueReader::popSignal is moved to each OneToOneUniQueue,
    //   we could clear just the remoteProcessId popSignal, further reducing the
    //   number of UDS notifications writers have to send.
    // * We could adjust theLastPopProcessId to try popping from the
    //   remoteProcessId queue first. That does not seem to help much and might
    //   introduce some bias, so we do not do that for now.
    clearAllReaderSignals();
}

void
Ipc::BaseMultiQueue::clearAllReaderSignals()
{
    QueueReader &reader = localReader();
    debugs(54, 7, "reader: " << reader.id);
    reader.clearSignal();
}

const Ipc::QueueReader::Balance &
Ipc::BaseMultiQueue::balance(const int remoteProcessId) const
{
    const QueueReader &r = remoteReader(remoteProcessId);
    return r.balance;
}

const Ipc::QueueReader::Rate &
Ipc::BaseMultiQueue::rateLimit(const int remoteProcessId) const
{
    const QueueReader &r = remoteReader(remoteProcessId);
    return r.rateLimit;
}

Ipc::OneToOneUniQueue &
Ipc::BaseMultiQueue::inQueue(const int remoteProcessId)
{
    const OneToOneUniQueue &queue =
        const_cast<const BaseMultiQueue *>(this)->inQueue(remoteProcessId);
    return const_cast<OneToOneUniQueue &>(queue);
}

Ipc::OneToOneUniQueue &
Ipc::BaseMultiQueue::outQueue(const int remoteProcessId)
{
    const OneToOneUniQueue &queue =
        const_cast<const BaseMultiQueue *>(this)->outQueue(remoteProcessId);
    return const_cast<OneToOneUniQueue &>(queue);
}

Ipc::QueueReader &
Ipc::BaseMultiQueue::localReader()
{
    const QueueReader &reader =
        const_cast<const BaseMultiQueue *>(this)->localReader();
    return const_cast<QueueReader &>(reader);
}

Ipc::QueueReader &
Ipc::BaseMultiQueue::remoteReader(const int remoteProcessId)
{
    const QueueReader &reader =
        const_cast<const BaseMultiQueue *>(this)->remoteReader(remoteProcessId);
    return const_cast<QueueReader &>(reader);
}

// FewToFewBiQueue

Ipc::FewToFewBiQueue::Owner *
Ipc::FewToFewBiQueue::Init(const String &id, const int groupASize, const int groupAIdOffset, const int groupBSize, const int groupBIdOffset, const unsigned int maxItemSize, const int capacity)
{
    return new Owner(id, groupASize, groupAIdOffset, groupBSize, groupBIdOffset, maxItemSize, capacity);
}

Ipc::FewToFewBiQueue::FewToFewBiQueue(const String &id, const Group aLocalGroup, const int aLocalProcessId):
    BaseMultiQueue(aLocalProcessId),
    metadata(shm_old(Metadata)(MetadataId(id).termedBuf())),
    queues(shm_old(OneToOneUniQueues)(QueuesId(id).termedBuf())),
    readers(shm_old(QueueReaders)(ReadersId(id).termedBuf())),
    theLocalGroup(aLocalGroup)
{
    Must(queues->theCapacity == size_t(metadata->theGroupASize) * size_t(metadata->theGroupBSize) * 2);
    Must(readers->theCapacity == size_t(metadata->theGroupASize) + size_t(metadata->theGroupBSize));

    debugs(54, 7, "queue " << id << " reader: " << localReader().id);
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

const Ipc::OneToOneUniQueue &
Ipc::FewToFewBiQueue::oneToOneQueue(const Group fromGroup, const int fromProcessId, const Group toGroup, const int toProcessId) const
{
    return (*queues)[oneToOneQueueIndex(fromGroup, fromProcessId, toGroup, toProcessId)];
}

const Ipc::OneToOneUniQueue &
Ipc::FewToFewBiQueue::inQueue(const int remoteProcessId) const
{
    return oneToOneQueue(remoteGroup(), remoteProcessId,
                         theLocalGroup, theLocalProcessId);
}

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

const Ipc::QueueReader &
Ipc::FewToFewBiQueue::localReader() const
{
    return readers->theReaders[readerIndex(theLocalGroup, theLocalProcessId)];
}

const Ipc::QueueReader &
Ipc::FewToFewBiQueue::remoteReader(const int processId) const
{
    return readers->theReaders[readerIndex(remoteGroup(), processId)];
}

int
Ipc::FewToFewBiQueue::remotesCount() const
{
    return theLocalGroup == groupA ? metadata->theGroupBSize :
           metadata->theGroupASize;
}

int
Ipc::FewToFewBiQueue::remotesIdOffset() const
{
    return theLocalGroup == groupA ? metadata->theGroupBIdOffset :
           metadata->theGroupAIdOffset;
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

// MultiQueue

Ipc::MultiQueue::Owner *
Ipc::MultiQueue::Init(const String &id, const int processCount, const int processIdOffset, const unsigned int maxItemSize, const int capacity)
{
    return new Owner(id, processCount, processIdOffset, maxItemSize, capacity);
}

Ipc::MultiQueue::MultiQueue(const String &id, const int localProcessId):
    BaseMultiQueue(localProcessId),
    metadata(shm_old(Metadata)(MetadataId(id).termedBuf())),
    queues(shm_old(OneToOneUniQueues)(QueuesId(id).termedBuf())),
    readers(shm_old(QueueReaders)(ReadersId(id).termedBuf()))
{
    Must(queues->theCapacity == size_t(metadata->theProcessCount) * size_t(metadata->theProcessCount));
    Must(readers->theCapacity == size_t(metadata->theProcessCount));

    debugs(54, 7, "queue " << id << " reader: " << localReader().id);
}

bool
Ipc::MultiQueue::validProcessId(const int processId) const
{
    return metadata->theProcessIdOffset <= processId &&
           processId < metadata->theProcessIdOffset + metadata->theProcessCount;
}

const Ipc::OneToOneUniQueue &
Ipc::MultiQueue::oneToOneQueue(const int fromProcessId, const int toProcessId) const
{
    assert(validProcessId(fromProcessId));
    assert(validProcessId(toProcessId));
    const int fromIndex = fromProcessId - metadata->theProcessIdOffset;
    const int toIndex = toProcessId - metadata->theProcessIdOffset;
    const int index = fromIndex * metadata->theProcessCount + toIndex;
    return (*queues)[index];
}

const Ipc::QueueReader &
Ipc::MultiQueue::reader(const int processId) const
{
    assert(validProcessId(processId));
    const int index = processId - metadata->theProcessIdOffset;
    return readers->theReaders[index];
}

const Ipc::OneToOneUniQueue &
Ipc::MultiQueue::inQueue(const int remoteProcessId) const
{
    return oneToOneQueue(remoteProcessId, theLocalProcessId);
}

const Ipc::OneToOneUniQueue &
Ipc::MultiQueue::outQueue(const int remoteProcessId) const
{
    return oneToOneQueue(theLocalProcessId, remoteProcessId);
}

const Ipc::QueueReader &
Ipc::MultiQueue::localReader() const
{
    return reader(theLocalProcessId);
}

const Ipc::QueueReader &
Ipc::MultiQueue::remoteReader(const int processId) const
{
    return reader(processId);
}

int
Ipc::MultiQueue::remotesCount() const
{
    return metadata->theProcessCount;
}

int
Ipc::MultiQueue::remotesIdOffset() const
{
    return metadata->theProcessIdOffset;
}

Ipc::MultiQueue::Metadata::Metadata(const int aProcessCount, const int aProcessIdOffset):
    theProcessCount(aProcessCount), theProcessIdOffset(aProcessIdOffset)
{
    Must(theProcessCount > 0);
}

Ipc::MultiQueue::Owner::Owner(const String &id, const int processCount, const int processIdOffset, const unsigned int maxItemSize, const int capacity):
    metadataOwner(shm_new(Metadata)(MetadataId(id).termedBuf(), processCount, processIdOffset)),
    queuesOwner(shm_new(OneToOneUniQueues)(QueuesId(id).termedBuf(), processCount*processCount, maxItemSize, capacity)),
    readersOwner(shm_new(QueueReaders)(ReadersId(id).termedBuf(), processCount))
{
}

Ipc::MultiQueue::Owner::~Owner()
{
    delete metadataOwner;
    delete queuesOwner;
    delete readersOwner;
}

