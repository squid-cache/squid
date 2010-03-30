/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_KIDS_H
#define SQUID_IPC_KIDS_H

#include "Array.h"
#include "ipc/Kid.h"


/// a collection of kids
class Kids
{
public:
    Kids ();

private:
    Kids (const Kids&); ///< not implemented
    Kids& operator= (const Kids&); ///< not implemented

public:
    /// maintain n kids
    void init(size_t n);

    /// returns kid by pid
    Kid* find(pid_t pid);

    /// returns the kid by index, useful for kids iteration
    Kid& get(size_t i);

    /// whether all kids are hopeless
    bool allHopeless() const;

    /// whether all kids called exited happy
    bool allExitedHappy() const;

    /// whether all kids died from a given signal
    bool allSignaled(int sgnl) const;

    /// returns the number of kids
    size_t count() const;

private:
    Vector<Kid> storage;
};

extern Kids TheKids; ///< All kids being maintained

extern char KidName[NAME_MAX]; ///< current Squid process name (e.g., squid2)
extern int KidIdentifier; ///< current Squid process number (e.g., 4)


#endif /* SQUID_IPC_KIDS_H */
