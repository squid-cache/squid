/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_CONTENTLENGTH_INTERPRETER_H
#define SQUID_SRC_HTTP_CONTENTLENGTH_INTERPRETER_H

class String;

namespace Http
{

/// Finds the intended Content-Length value while parsing message-header fields.
/// Deals with complications such as value lists and/or repeated fields.
class ContentLengthInterpreter
{
public:
    explicit ContentLengthInterpreter(const int aDebugLevel);

    /// updates history based on the given message-header field
    /// \return true iff the field should be added/remembered for future use
    bool checkField(const String &field);

    /// intended Content-Length value if sawGood is set and sawBad is not set
    /// meaningless otherwise
    int64_t value;

    /* for debugging (declared here to minimize padding) */
    const char *headerWideProblem; ///< worst header-wide problem found (or nil)
    const int debugLevel; ///< debugging level for certain warnings

    /// whether a malformed Content-Length value was present
    bool sawBad;

    /// whether all remembered fields should be removed
    /// removed fields ought to be replaced with the intended value (if known)
    /// irrelevant if sawBad is set
    bool needsSanitizing;

    /// whether a valid field value was present, possibly among problematic ones
    /// irrelevant if sawBad is set
    bool sawGood;

protected:
    const char *findDigits(const char *prefix, const char *valueEnd) const;
    bool goodSuffix(const char *suffix, const char * const end) const;
    bool checkValue(const char *start, const int size);
    bool checkList(const String &list);
};

} // namespace Http

#endif /* SQUID_SRC_HTTP_CONTENTLENGTH_INTERPRETER_H */

