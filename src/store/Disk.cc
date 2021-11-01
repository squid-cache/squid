/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Swap Dir base object */

#include "squid.h"
#include "cache_cf.h"
#include "compat/strtoll.h"
#include "ConfigOption.h"
#include "ConfigParser.h"
#include "globals.h"
#include "Parsing.h"
#include "SquidConfig.h"
#include "Store.h"
#include "store/Disk.h"
#include "StoreFileSystem.h"
#include "tools.h"

Store::Disk::Disk(char const *aType): theType(aType),
    max_size(0), min_objsize(-1), max_objsize (-1),
    path(NULL), index(-1), disker(-1),
    repl(NULL), removals(0), scanned(0),
    cleanLog(NULL)
{
    fs.blksize = 1024;
}

Store::Disk::~Disk()
{
    // TODO: should we delete repl?
    xfree(path);
}

void
Store::Disk::create() {}

void
Store::Disk::dump(StoreEntry &)const {}

bool
Store::Disk::doubleCheck(StoreEntry &)
{
    return false;
}

void
Store::Disk::getStats(StoreInfoStats &stats) const
{
    if (!doReportStat())
        return;

    stats.swap.size = currentSize();
    stats.swap.capacity = maxSize();
    stats.swap.count = currentCount();
}

void
Store::Disk::stat(StoreEntry &output) const
{
    if (!doReportStat())
        return;

    storeAppendPrintf(&output, "Store Directory #%d (%s): %s\n", index, type(),
                      path);
    storeAppendPrintf(&output, "FS Block Size %d Bytes\n",
                      fs.blksize);
    statfs(output);

    if (repl) {
        storeAppendPrintf(&output, "Removal policy: %s\n", repl->_type);

        if (repl->Stats)
            repl->Stats(repl, &output);
    }
}

void
Store::Disk::statfs(StoreEntry &)const {}

void
Store::Disk::maintain() {}

uint64_t
Store::Disk::minSize() const
{
    // XXX: Not all disk stores use Config.Swap.lowWaterMark
    return ((maxSize() * Config.Swap.lowWaterMark) / 100);
}

int64_t
Store::Disk::minObjectSize() const
{
    // per-store min-size=N value is authoritative
    return min_objsize > -1 ? min_objsize : Config.Store.minObjectSize;
}

int64_t
Store::Disk::maxObjectSize() const
{
    // per-store max-size=N value is authoritative
    if (max_objsize > -1)
        return max_objsize;

    // store with no individual max limit is limited by configured maximum_object_size
    // or the total store size, whichever is smaller
    return min(static_cast<int64_t>(maxSize()), Config.Store.maxObjectSize);
}

void
Store::Disk::maxObjectSize(int64_t newMax)
{
    // negative values mean no limit (-1)
    if (newMax < 0) {
        max_objsize = -1; // set explicitly in case it had a non-default value previously
        return;
    }

    // prohibit values greater than total storage area size
    // but set max_objsize to the maximum allowed to override maximum_object_size global config
    if (static_cast<uint64_t>(newMax) > maxSize()) {
        debugs(47, DBG_PARSE_NOTE(2), "WARNING: Ignoring 'max-size' option for " << path <<
               " which is larger than total cache_dir size of " << maxSize() << " bytes.");
        max_objsize = maxSize();
        return;
    }

    max_objsize = newMax;
}

void
Store::Disk::reference(StoreEntry &) {}

bool
Store::Disk::dereference(StoreEntry &)
{
    return true; // keep in global store_table
}

void
Store::Disk::diskFull()
{
    if (currentSize() >= maxSize())
        return;

    max_size = currentSize();

    debugs(20, DBG_IMPORTANT, "WARNING: Shrinking cache_dir #" << index << " to " << currentSize() / 1024.0 << " KB");
}

bool
Store::Disk::objectSizeIsAcceptable(int64_t objsize) const
{
    // need either the expected or the already accumulated object size
    assert(objsize >= 0);
    return minObjectSize() <= objsize && objsize <= maxObjectSize();
}

bool
Store::Disk::canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const
{
    debugs(47,8, HERE << "cache_dir[" << index << "]: needs " <<
           diskSpaceNeeded << " <? " << max_objsize);

    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return false; // we do not store Squid-generated entries

    if (!objectSizeIsAcceptable(diskSpaceNeeded))
        return false; // does not satisfy size limits

    if (flags.read_only)
        return false; // cannot write at all

    if (currentSize() > maxSize())
        return false; // already overflowing

    /* Return 999 (99.9%) constant load; TODO: add a named constant for this */
    load = 999;
    return true; // kids may provide more tests and should report true load
}

/* Move to StoreEntry ? */
bool
Store::Disk::canLog(StoreEntry const &e)const
{
    if (!e.hasDisk())
        return false;

    if (!e.swappedOut())
        return false;

    if (e.swap_file_sz <= 0)
        return false;

    if (EBIT_TEST(e.flags, RELEASE_REQUEST))
        return false;

    if (EBIT_TEST(e.flags, KEY_PRIVATE))
        return false;

    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return false;

    return true;
}

void
Store::Disk::openLog() {}

void
Store::Disk::closeLog() {}

int
Store::Disk::writeCleanStart()
{
    return 0;
}

void
Store::Disk::writeCleanDone() {}

void
Store::Disk::logEntry(const StoreEntry &, int) const {}

char const *
Store::Disk::type() const
{
    return theType;
}

bool
Store::Disk::active() const
{
    if (IamWorkerProcess())
        return true;

    // we are inside a disker dedicated to this disk
    if (KidIdentifier == disker)
        return true;

    return false; // Coordinator, wrong disker, etc.
}

bool
Store::Disk::needsDiskStrand() const
{
    return false;
}

/* NOT performance critical. Really. Don't bother optimising for speed
 * - RBC 20030718
 */
ConfigOption *
Store::Disk::getOptionTree() const
{
    ConfigOptionVector *result = new ConfigOptionVector;
    result->options.push_back(new ConfigOptionAdapter<Disk>(*const_cast<Disk*>(this), &Store::Disk::optionReadOnlyParse, &Store::Disk::optionReadOnlyDump));
    result->options.push_back(new ConfigOptionAdapter<Disk>(*const_cast<Disk*>(this), &Store::Disk::optionObjectSizeParse, &Store::Disk::optionObjectSizeDump));
    return result;
}

void
Store::Disk::parseOptions(int isaReconfig)
{
    const bool old_read_only = flags.read_only;
    char *name, *value;

    ConfigOption *newOption = getOptionTree();

    while ((name = ConfigParser::NextToken()) != NULL) {
        value = strchr(name, '=');

        if (value) {
            *value = '\0';  /* cut on = */
            ++value;
        }

        debugs(3,2, "cache_dir " << name << '=' << (value ? value : ""));

        if (newOption)
            if (!newOption->parse(name, value, isaReconfig)) {
                self_destruct();
                return;
            }
    }

    delete newOption;

    /*
     * Handle notifications about reconfigured single-options with no value
     * where the removal of the option cannot be easily detected in the
     * parsing...
     */

    if (isaReconfig) {
        if (old_read_only != flags.read_only) {
            debugs(3, DBG_IMPORTANT, "Cache dir '" << path << "' now " << (flags.read_only ? "No-Store" : "Read-Write"));
        }
    }
}

void
Store::Disk::dumpOptions(StoreEntry * entry) const
{
    ConfigOption *newOption = getOptionTree();

    if (newOption)
        newOption->dump(entry);

    delete newOption;
}

bool
Store::Disk::optionReadOnlyParse(char const *option, const char *value, int)
{
    if (strcmp(option, "no-store") != 0 && strcmp(option, "read-only") != 0)
        return false;

    if (strcmp(option, "read-only") == 0) {
        debugs(3, DBG_PARSE_NOTE(3), "UPGRADE WARNING: Replace cache_dir option 'read-only' with 'no-store'.");
    }

    bool read_only = 0;

    if (value)
        read_only = (xatoi(value) != 0);
    else
        read_only = true;

    flags.read_only = read_only;

    return true;
}

void
Store::Disk::optionReadOnlyDump(StoreEntry * e) const
{
    if (flags.read_only)
        storeAppendPrintf(e, " no-store");
}

bool
Store::Disk::optionObjectSizeParse(char const *option, const char *value, int isaReconfig)
{
    int64_t *val;
    if (strcmp(option, "max-size") == 0) {
        val = &max_objsize;
    } else if (strcmp(option, "min-size") == 0) {
        val = &min_objsize;
    } else
        return false;

    if (!value) {
        self_destruct();
        return false;
    }

    int64_t size = strtoll(value, NULL, 10);

    if (isaReconfig && *val != size) {
        if (allowOptionReconfigure(option)) {
            debugs(3, DBG_IMPORTANT, "cache_dir '" << path << "' object " <<
                   option << " now " << size << " Bytes");
        } else {
            debugs(3, DBG_IMPORTANT, "WARNING: cache_dir '" << path << "' "
                   "object " << option << " cannot be changed dynamically, " <<
                   "value left unchanged (" << *val << " Bytes)");
            return true;
        }
    }

    *val = size;

    return true;
}

void
Store::Disk::optionObjectSizeDump(StoreEntry * e) const
{
    if (min_objsize != -1)
        storeAppendPrintf(e, " min-size=%" PRId64, min_objsize);

    if (max_objsize != -1)
        storeAppendPrintf(e, " max-size=%" PRId64, max_objsize);
}

// some SwapDirs may maintain their indexes and be able to lookup an entry key
StoreEntry *
Store::Disk::get(const cache_key *)
{
    return NULL;
}

