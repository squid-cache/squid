/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "store/libstore.la"
#include "tests/STUB.h"

#include "store/Controller.h"
namespace Store
{
Controller::Controller() {STUB_NOP}
Controller::~Controller() {STUB_NOP}
void Controller::create() STUB
void Controller::init() STUB
uint64_t Controller::maxSize() const STUB_RETVAL(0)
uint64_t Controller::minSize() const STUB_RETVAL(0)
uint64_t Controller::currentSize() const STUB_RETVAL(0)
uint64_t Controller::currentCount() const STUB_RETVAL(0)
int64_t Controller::maxObjectSize() const STUB_RETVAL(0)
void Controller::getStats(StoreInfoStats &) const STUB
void Controller::stat(StoreEntry &) const STUB
void Controller::sync() STUB
void Controller::maintain() STUB
void Controller::evictCached(StoreEntry &) STUB
void Controller::evictIfFound(const cache_key *) STUB
int Controller::callback() STUB
StoreEntry *Controller::find(const cache_key *) STUB_RETVAL(nullptr)
StoreEntry *Controller::peek(const cache_key *) STUB_RETVAL(nullptr)
StoreEntry *Controller::findCallbackXXX(const cache_key *) STUB_RETVAL(nullptr)
bool Controller::markedForDeletion(const cache_key *) const STUB_RETVAL(false)
bool Controller::markedForDeletionAndAbandoned(const StoreEntry &) const STUB_RETVAL(false)
bool Controller::hasReadableDiskEntry(const StoreEntry &) const STUB_RETVAL(false)
int64_t Controller::accumulateMore(StoreEntry &) const STUB_RETVAL(0)
void Controller::updateLimits() STUB
void Controller::handleIdleEntry(StoreEntry &) STUB
void Controller::freeMemorySpace(const int) STUB
void Controller::memoryOut(StoreEntry &, const bool) STUB
void Controller::updateOnNotModified(StoreEntry *, StoreEntry &) STUB
bool Controller::allowCollapsing(StoreEntry *, const RequestFlags &, const HttpRequestMethod &) STUB_RETVAL(false)
void Controller::addReading(StoreEntry *, const cache_key *) STUB
void Controller::addWriting(StoreEntry *, const cache_key *) STUB
bool Controller::transientsReader(const StoreEntry &) const STUB_RETVAL(false)
bool Controller::transientsWriter(const StoreEntry &) const STUB_RETVAL(false)
void Controller::transientsCompleteWriting(StoreEntry &) STUB
void Controller::syncCollapsed(const sfileno) STUB
void Controller::stopSharing(StoreEntry &) STUB
int Controller::transientReaders(const StoreEntry &) const STUB_RETVAL(0)
void Controller::transientsDisconnect(StoreEntry &) STUB
void Controller::transientsClearCollapsingRequirement(StoreEntry &) STUB
void Controller::memoryDisconnect(StoreEntry &) STUB
StoreSearch *Controller::search() STUB_RETVAL(nullptr)
bool Controller::SmpAware() STUB_RETVAL(false)
int Controller::store_dirs_rebuilding = 0;
Controller nil;
Controller &Root() STUB_RETVAL(Store::nil)
void Init(Controller *) STUB
void FreeMemory() STUB
}

#include "store/Disk.h"
namespace Store
{
Disk::Disk(char const *) {STUB}
Disk::~Disk() {STUB}
char const *Disk::type() const STUB_RETVAL(nullptr)
bool Disk::needsDiskStrand() const STUB_RETVAL(false)
bool Disk::active() const STUB_RETVAL(false)
void Disk::diskFull() STUB
void Disk::create() STUB
StoreEntry *Disk::get(const cache_key *) STUB_RETVAL(nullptr)
uint64_t Disk::minSize() const STUB_RETVAL(0)
int64_t Disk::maxObjectSize() const STUB_RETVAL(0)
void Disk::getStats(StoreInfoStats &) const STUB
void Disk::stat(StoreEntry &) const STUB
void Disk::reference(StoreEntry &) STUB
bool Disk::dereference(StoreEntry &) STUB_RETVAL(false)
void Disk::maintain() STUB
int64_t Disk::minObjectSize() const STUB_RETVAL(0)
void Disk::maxObjectSize(int64_t) STUB
bool Disk::objectSizeIsAcceptable(int64_t) const STUB_RETVAL(false)
void Disk::parseOptions(int) STUB
void Disk::dumpOptions(StoreEntry *) const STUB
ConfigOption *Disk::getOptionTree() const STUB_RETVAL(nullptr)
void Disk::dump(StoreEntry &) const STUB
bool Disk::doubleCheck(StoreEntry &) STUB_RETVAL(false)
void Disk::statfs(StoreEntry &) const STUB
bool Disk::canLog(StoreEntry const &) const STUB_RETVAL(false)
void Disk::openLog() STUB
void Disk::closeLog() STUB
void Disk::logEntry(const StoreEntry &, int) const STUB
int Disk::writeCleanStart() STUB_RETVAL(0)
void Disk::writeCleanDone() STUB
}

#include "store/Disks.h"
namespace Store
{
Disks::Disks() {STUB}
void Disks::create() STUB
void Disks::init() STUB
StoreEntry *Disks::get(const cache_key *) STUB_RETVAL(nullptr)
uint64_t Disks::maxSize() const STUB_RETVAL(0)
uint64_t Disks::minSize() const STUB_RETVAL(0)
uint64_t Disks::currentSize() const STUB_RETVAL(0)
uint64_t Disks::currentCount() const STUB_RETVAL(0)
int64_t Disks::maxObjectSize() const STUB_RETVAL(0)
void Disks::getStats(StoreInfoStats &) const STUB
void Disks::stat(StoreEntry &) const STUB
void Disks::sync() STUB
void Disks::reference(StoreEntry &) STUB
bool Disks::dereference(StoreEntry &) STUB_RETVAL(false)
void Disks::updateHeaders(StoreEntry *) STUB
void Disks::maintain() STUB
bool Disks::anchorToCache(StoreEntry &, bool &) STUB_RETVAL(false)
bool Disks::updateAnchored(StoreEntry &) STUB_RETVAL(false)
void Disks::evictCached(StoreEntry &) STUB
void Disks::evictIfFound(const cache_key *) STUB
int Disks::callback() STUB_RETVAL(0)
void Disks::updateLimits() STUB
int64_t Disks::accumulateMore(const StoreEntry&) const STUB_RETVAL(0)
bool Disks::SmpAware() STUB_RETVAL(false)
bool Disks::hasReadableEntry(const StoreEntry &) const STUB_RETVAL(false)
}
void storeDirOpenSwapLogs(void) STUB
int storeDirWriteCleanLogs(int) STUB_RETVAL(0)
void storeDirCloseSwapLogs(void) STUB
void allocate_new_swapdir(Store::DiskConfig *) STUB
void free_cachedir(Store::DiskConfig *) STUB
STDIRSELECT *storeDirSelectSwapDir = nullptr;
void storeDirSwapLog(const StoreEntry *, int) STUB

#include "store/LocalSearch.h"
namespace Store
{
StoreSearch *NewLocalSearch() STUB_RETVAL(nullptr)
}

