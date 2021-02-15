#ifndef SQUID_DEBUG_MESSAGES_H
#define SQUID_DEBUG_MESSAGES_H

#include "Debug.h"

#include <limits>
#include <array>

// XXX: Replace Debug class with namespace and use that namespace here.

/// an identifier for messages supporting configuration via cache_log_message
typedef unsigned int DebugMessageId;

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
        if (configured())
            return (count_++ >= limit) ? DBG_DATA : level;
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

/// The exact number of supported configurable messages. Increase as needed.
constexpr size_t DebugMessageCount = 64;
/// configurable messages indexed by DebugMessageId
typedef std::array<DebugMessage, DebugMessageCount> DebugMessages;
/// all configurable debugging messages
extern DebugMessages TheDebugMessages;

// Using a template allows us to check message ID range at compile time.
/// \returns configured debugging level for the given message or defaultLevel
template <DebugMessageId id>
inline int
DebugMessageLevel(const int defaultLevel)
{
    static_assert(id > 0, "debugs() message ID must be positive");
    static_assert(id < DebugMessageCount, "debugs() message ID too large");
    return TheDebugMessages[id].currentLevel(defaultLevel);
}

/* convenience macros for calling DebugMessageLevel */
#define Critical(id) DebugMessageLevel<id>(DBG_CRITICAL)
#define Important(id) DebugMessageLevel<id>(DBG_IMPORTANT)
#define Dbg(id, defaultLevel) DebugMessageLevel<id>(defaultLevel)

#endif /* SQUID_DEBUG_MESSAGES_H */

