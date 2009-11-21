
/*
 * $Id$
 *
 * DEBUG: section 20    Swap Dir base object
 * AUTHOR: Robert Collins
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "SwapDir.h"
#include "StoreFileSystem.h"
#include "ConfigOption.h"

SwapDir::~SwapDir()
{
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
SwapDir::stat(StoreEntry &output) const
{
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

size_t
SwapDir::minSize() const
{
    return (size_t) (((float) maxSize() *
                      (float) Config.Swap.lowWaterMark) / 100.0);
}

void
SwapDir::reference(StoreEntry &) {}

void
SwapDir::dereference(StoreEntry &) {}

int
SwapDir::callback()
{
    return 0;
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

/* NOT performance critical. Really. Don't bother optimising for speed
 * - RBC 20030718
 */
ConfigOption *
SwapDir::getOptionTree() const
{
    ConfigOptionVector *result = new ConfigOptionVector;
    result->options.push_back(new ConfigOptionAdapter<SwapDir>(*const_cast<SwapDir *>(this), &SwapDir::optionReadOnlyParse, &SwapDir::optionReadOnlyDump));
    result->options.push_back(new ConfigOptionAdapter<SwapDir>(*const_cast<SwapDir *>(this), &SwapDir::optionMaxSizeParse, &SwapDir::optionMaxSizeDump));
    return result;
}

void
SwapDir::parseOptions(int isaReconfig)
{
    unsigned int old_read_only = flags.read_only;
    char *name, *value;

    ConfigOption *newOption = getOptionTree();

    while ((name = strtok(NULL, w_space)) != NULL) {
        value = strchr(name, '=');

        if (value)
            *value++ = '\0';	/* cut on = */

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
            debugs(3, 1, "Cache dir '" << path << "' now " << (flags.read_only ? "No-Store" : "Read-Write"));
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

    int read_only = 0;

    if (value)
        read_only = xatoi(value);
    else
        read_only = 1;

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
SwapDir::optionMaxSizeParse(char const *option, const char *value, int isaReconfig)
{
    if (strcmp(option, "max-size") != 0)
        return false;

    if (!value)
        self_destruct();

    int64_t size = strtoll(value, NULL, 10);

    if (isaReconfig && max_objsize != size)
        debugs(3, 1, "Cache dir '" << path << "' max object size now " << size);

    max_objsize = size;

    return true;
}

void
SwapDir::optionMaxSizeDump(StoreEntry * e) const
{
    if (max_objsize != -1)
        storeAppendPrintf(e, " max-size=%"PRId64, max_objsize);
}

/* Swapdirs do not have an index of their own - thus they ask their parent..
 * but the parent child relationship isn't implemented yet
 */
StoreEntry *

SwapDir::get
(const cache_key *key)
{
    return Store::Root().get(key);
}

void

SwapDir::get
(String const key, STOREGETCLIENT aCallback, void *aCallbackData)
{
    fatal("not implemented");
}
