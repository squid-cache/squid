/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef HTTPBODY_H_
#define HTTPBODY_H_

#include "MemBuf.h"

/** Representation of a short predetermined message
 *
 * This class is useful to represent short HTTP messages, whose
 * contents are known in advance, e.g. error messages
 */
class HttpBody
{
public:
    HttpBody();
    ~HttpBody();
    /** absorb the MemBuf, discarding anything currently stored
     *
     * After this call the lifetime of the passed MemBuf is managed
     * by the HttpBody.
     */
    void setMb(MemBuf *);

    /** output the HttpBody contents into the supplied container
     *
     * \note content is not cleared by the output operation
     */
    void packInto(Packable *) const;

    /// clear the HttpBody content
    void clear();

    /// \return true if there is any content in the HttpBody
    bool hasContent() const { return (mb->contentSize()>0); }

    /// \return size of the HttpBody's message content
    mb_size_t contentSize() const { return mb->contentSize(); }

    /// \return pointer to the storage of the HttpBody
    char *content() const { return mb->content(); }
private:
    HttpBody& operator=(const HttpBody&); //not implemented
    HttpBody(const HttpBody&); // not implemented
    MemBuf *mb;
};

#endif /* HTTPBODY_H_ */

