/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef HTTPBODY_H_
#define HTTPBODY_H_

#include "sbuf/SBuf.h"

class Packable; // TODO: Add and use base/forward.h.

/** Representation of a short predetermined message
 *
 * This class is useful to represent short HTTP messages, whose
 * contents are known in advance, e.g. error messages
 */
class HttpBody
{
public:
    HttpBody() {}

    void set(const SBuf &newContent) { raw_ = newContent; }

    /** output the HttpBody contents into the supplied container
     *
     * \note content is not cleared by the output operation
     */
    void packInto(Packable *) const;

    /// clear the HttpBody content
    void clear() { raw_.clear(); }

    /// \return true if there is any content in the HttpBody
    bool hasContent() const { return raw_.length() > 0; }

    /// \return size of the HttpBody's message content
    size_t contentSize() const { return raw_.length(); }

    /// \return body bytes (possibly not nil-terminated)
    const char *content() const { return raw_.rawContent(); }

private:
    HttpBody& operator=(const HttpBody&); //not implemented
    HttpBody(const HttpBody&); // not implemented

    SBuf raw_; // body bytes
};

#endif /* HTTPBODY_H_ */

