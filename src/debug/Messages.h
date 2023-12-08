/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Debug Routines */

#ifndef SQUID_DEBUG_MESSAGES_H
#define SQUID_DEBUG_MESSAGES_H

#include "debug/Stream.h"

#include <array>
#include <limits>

// XXX: Replace Debug class with namespace and use that namespace here.

/// an identifier for messages supporting configuration via cache_log_message
typedef size_t DebugMessageId;

/// manages configurable aspects of a debugs() message
class DebugMessage
{
public:
    /// whether the logging of this message has been customized
    bool configured() const { return id > 0; }

    /// whether the default logging level of this message has been altered
    bool levelled() const { return level >= 0; }

    /// whether the number of logging attempts have been limited
    bool limited() const { return limit < std::numeric_limits<decltype(limit)>::max(); }

    /// \returns appropriate debugging level for the message
    int currentLevel(const int defaultLevel) const {
        if (configured()) {
            if (count_++ < limit)
                return level;
            return (level <= DBG_IMPORTANT) ? 3 : 8;
        }
        return defaultLevel;
    }

    /// message identifier or, if the message has not been configured, zero
    DebugMessageId id = 0;

    /* all these configurable members are ignored unless configured() */

    /// debugging level (i.e., the second debugs() parameter) or -1
    int level = -1;

    /// logging attempts beyond this limit are logged at the DBG_DATA level
    uint64_t limit = std::numeric_limits<uint64_t>::max();

private:
    /// the total number of attempts to log this message if it was configured()
    mutable uint64_t count_ = 0;
};

/// The maximum used DebugMessage::id plus 1. Increase as you add new IDs.
constexpr DebugMessageId DebugMessageIdUpperBound = 70;

/// a collection of DebugMessage objects (with fast access by message IDs)
class DebugMessages
{
public:
    /// configurable messages indexed by their IDs
    typedef std::array<DebugMessage, DebugMessageIdUpperBound> Storage;
    Storage messages;
};

/// Global configuration for DebugMessageLevel() (where/when supported).
inline DebugMessages *DebugMessagesConfig = nullptr;

// Using a template allows us to check message ID range at compile time.
/// \returns configured debugging level for the given message or defaultLevel
template <DebugMessageId id>
inline int
DebugMessageLevel(const int defaultLevel)
{
    static_assert(id > 0, "debugs() message ID must be positive");
    static_assert(id < DebugMessageIdUpperBound, "debugs() message ID must be smaller than DebugMessageIdUpperBound");
    if (const auto configured = DebugMessagesConfig)
        return (configured->messages)[id].currentLevel(defaultLevel);
    return defaultLevel;
}

/* convenience macros for calling DebugMessageLevel */
#define Critical(id) DebugMessageLevel<id>(DBG_CRITICAL)
#define Important(id) DebugMessageLevel<id>(DBG_IMPORTANT)
#define Dbg(id, defaultLevel) DebugMessageLevel<id>(defaultLevel)

#endif /* SQUID_DEBUG_MESSAGES_H */

