/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
#include "StoreFileSystem.h"
#include "SwapDir.h"
#include "tools.h"

SwapDir::SwapDir(char const *aType): theType(aType),
    max_size(0), min_objsize(0), max_objsize (-1),
    path(NULL), index(-1), disker(-1),
    repl(NULL), removals(0), scanned(0),
    cleanLog(NULL)
{
    fs.blksize = 1024;
}

SwapDir::~SwapDir()
{
    // TODO: should we delete repl?
    xfree(path);
}

void
SwapDir::create() {}

void
SwapDir::dump(StoreEntry &)const {}

bool
SwapDir::doubleCheck(StoreEntry &)
{
    return false;
}

void
SwapDir::unlink(StoreEntry &) {}

void
SwapDir::getStats(StoreInfoStats &stats) const
{
    if (!doReportStat())
        return;

    stats.swap.size = currentSize();
    stats.swap.capacity = maxSize();
    stats.swap.count = currentCount();
}

void
SwapDir::stat(StoreEntry &output) const
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
SwapDir::statfs(StoreEntry &)const {}

void
SwapDir::maintain() {}

uint64_t
SwapDir::minSize() const
{
    return ((maxSize() * Config.Swap.lowWaterMark) / 100);
}

int64_t
SwapDir::maxObjectSize() const
{
    // per-store max-size=N value is authoritative
    if (max_objsize > -1)
        return max_objsize;

    // store with no individual max limit is limited by configured maximum_object_size
    // or the total store size, whichever is smaller
    return min(static_cast<int64_t>(maxSize()), Config.Store.maxObjectSize);
}

void
SwapDir::maxObjectSize(int64_t newMax)
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
SwapDir::reference(StoreEntry &) {}

bool
SwapDir::dereference(StoreEntry &, bool)
{
    return true; // keep in global store_table
}

int
SwapDir::callback()
{
    return 0;
}

bool
SwapDir::canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const
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

void
SwapDir::sync() {}

/* Move to StoreEntry ? */
bool
SwapDir::canLog(StoreEntry const &e)const
{
    if (e.swap_filen < 0)
        return false;

    if (e.swap_status != SWAPOUT_DONE)
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
SwapDir::openLog() {}

void
SwapDir::closeLog() {}

int
SwapDir::writeCleanStart()
{
    return 0;
}

void
SwapDir::writeCleanDone() {}

void
SwapDir::logEntry(const StoreEntry & e, int op) const {}

char const *
SwapDir::type() const
{
    return theType;
}

bool
SwapDir::active() const
{
    if (IamWorkerProcess())
        return true;

    // we are inside a disker dedicated to this disk
    if (KidIdentifier == disker)
        return true;

    return false; // Coordinator, wrong disker, etc.
}

bool
SwapDir::needsDiskStrand() const
{
    return false;
}

/* NOT performance critical. Really. Don't bother optimising for speed
 * - RBC 20030718
 */
ConfigOption *
SwapDir::getOptionTree() const
{
    ConfigOptionVector *result = new ConfigOptionVector;
    result->options.push_back(new ConfigOptionAdapter<SwapDir>(*const_cast<SwapDir *>(this), &SwapDir::optionReadOnlyParse, &SwapDir::optionReadOnlyDump));
    result->options.push_back(new ConfigOptionAdapter<SwapDir>(*const_cast<SwapDir *>(this), &SwapDir::optionObjectSizeParse, &SwapDir::optionObjectSizeDump));
    return result;
}

void
SwapDir::parseOptions(int isaReconfig)
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

        debugs(3,2, "SwapDir::parseOptions: parsing store option '" << name << "'='" << (value ? value : "") << "'");

        if (newOption)
            if (!newOption->parse(name, value, isaReconfig))
                self_destruct();
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
SwapDir::dumpOptions(StoreEntry * entry) const
{
    ConfigOption *newOption = getOptionTree();

    if (newOption)
        newOption->dump(entry);

    delete newOption;
}

bool
SwapDir::optionReadOnlyParse(char const *option, const char *value, int isaReconfig)
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
SwapDir::optionReadOnlyDump(StoreEntry * e) const
{
    if (flags.read_only)
        storeAppendPrintf(e, " no-store");
}

bool
SwapDir::optionObjectSizeParse(char const *option, const char *value, int isaReconfig)
{
    int64_t *val;
    if (strcmp(option, "max-size") == 0) {
        val = &max_objsize;
    } else if (strcmp(option, "min-size") == 0) {
        val = &min_objsize;
    } else
        return false;

    if (!value)
        self_destruct();

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
SwapDir::optionObjectSizeDump(StoreEntry * e) const
{
    if (min_objsize != 0)
        storeAppendPrintf(e, " min-size=%" PRId64, min_objsize);

    if (max_objsize != -1)
        storeAppendPrintf(e, " max-size=%" PRId64, max_objsize);
}

// some SwapDirs may maintain their indexes and be able to lookup an entry key
StoreEntry *
SwapDir::get(const cache_key *key)
{
    return NULL;
}

void
SwapDir::get(String const key, STOREGETCLIENT aCallback, void *aCallbackData)
{
    fatal("not implemented");
}

