/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_CONTENTLENGTH_INTERPRETER_H
#define SQUID_SRC_HTTP_CONTENTLENGTH_INTERPRETER_H

#include "http/StatusCode.h"

class String;

namespace Http
{

/// Finds the intended Content-Length value while parsing message-header fields.
/// Deals with complications such as value lists and/or repeated fields.
class ContentLengthInterpreter
{
public:
    ContentLengthInterpreter();

    /// updates history based on the given message-header field
    /// \return true iff the field should be added/remembered for future use
    bool checkField(const String &field);

    /// prohibits Content-Length in 1xx and 204 responses
    void applyStatusCodeRules(const StatusCode code) {
        if (!prohibitedAndIgnored_ && ProhibitsContentLength(code))
            prohibitedAndIgnored_ = (code == scNoContent) ? "prohibited and ignored in the 204 response" :
                                    "prohibited and ignored the 1xx response";
    }

    // TODO: implement
    /// prohibits Content-Length in GET/HEAD requests
    // void applyRequestMethodRules(const Http::MethodType method);

    /// prohibits Content-Length in trailer
    void applyTrailerRules() {
        if (!prohibitedAndIgnored_)
            prohibitedAndIgnored_ = "prohibited in trailers";
    }

    const char *prohibitedAndIgnored() const { return prohibitedAndIgnored_; }

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

private:
    /// whether and why Content-Length is prohibited
    const char *prohibitedAndIgnored_;
};

} // namespace Http

#endif /* SQUID_SRC_HTTP_CONTENTLENGTH_INTERPRETER_H */

