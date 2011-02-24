/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "ipc/Kids.h"

Kids TheKids;
KidName TheKidName;

Kids::Kids()
{
}

/// maintain n kids
void Kids::init(size_t n)
{
    assert(n > 0);

    if (storage.size() > 0)
        storage.clean();

    storage.reserve(n);

    char kid_name[32];

    // add Kid records for all n main strands
    for (size_t i = 1; i <= n; ++i) {
        snprintf(kid_name, sizeof(kid_name), "(squid-%d)", (int)i);
        storage.push_back(Kid(kid_name));
    }

    // if coordination is needed, add a Kid record for Coordinator
    if (n > 1) {
        snprintf(kid_name, sizeof(kid_name), "(squid-coord-%d)", (int)(n + 1));
        storage.push_back(Kid(kid_name));
    }
}

/// returns kid by pid
Kid* Kids::find(pid_t pid)
{
    assert(pid > 0);
    assert(count() > 0);

    for (size_t i = 0; i < storage.size(); ++i) {
        if (storage[i].getPid() == pid)
            return &storage[i];
    }
    return NULL;
}

/// returns the kid by index, useful for kids iteration
Kid& Kids::get(size_t i)
{
    assert(i < count());
    return storage[i];
}

/// whether all kids are hopeless
bool Kids::allHopeless() const
{
    for (size_t i = 0; i < storage.size(); ++i) {
        if (!storage[i].hopeless())
            return false;
    }
    return true;
}

/// whether all kids called exited happy
bool Kids::allExitedHappy() const
{
    for (size_t i = 0; i < storage.size(); ++i) {
        if (!storage[i].exitedHappy())
            return false;
    }
    return true;
}

/// whether all kids died from a given signal
bool Kids::allSignaled(int sgnl) const
{
    for (size_t i = 0; i < storage.size(); ++i) {
        if (!storage[i].signaled(sgnl))
            return false;
    }
    return true;
}

/// returns the number of kids
size_t Kids::count() const
{
    return storage.size();
}
