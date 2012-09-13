/*
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
    /// initialize all kid records based on Config
    void init();

    /// returns kid by pid
    Kid* find(pid_t pid);

    /// returns the kid by index, useful for kids iteration
    Kid& get(size_t i);

    /// whether all kids are hopeless
    bool allHopeless() const;

    /// whether all kids called exited happy
    bool allExitedHappy() const;

    /// whether some kids died from a given signal
    bool someSignaled(const int sgnl) const;

    /// whether some kids are running
    bool someRunning() const;

    /// whether some kids should be restarted by master
    bool shouldRestartSome() const;

    /// returns the number of kids
    size_t count() const;

private:
    Vector<Kid> storage;
};

extern Kids TheKids; ///< All kids being maintained

typedef char KidName[64]; ///< Squid process name (e.g., "squid-coord")
extern KidName TheKidName; ///< current Squid process name

#endif /* SQUID_IPC_KIDS_H */
