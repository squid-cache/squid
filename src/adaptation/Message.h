/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ADAPTATION_MESSAGE_H
#define SQUID_SRC_ADAPTATION_MESSAGE_H

#include "base/RefCount.h"
#include "http/forward.h"

class BodyPipe;
typedef RefCount<BodyPipe> BodyPipePointer;

namespace Adaptation
{

// Manages the header and the body of an HTTP message being worked on.
// Adaptation transactions use this class for virgin and adapted HTTP messages.
// TODO: remove this class after adding refcounted message pointers and
// after making sure nobody abruptly clears the Http::Message::body_pipe pointer.
class Message
{

public:
    typedef Http::Message Header;

    Message();
    Message(Header *aHeader);
    ~Message();

    void clear();
    void set(Header *aHeader);

    static void ShortCircuit(Message &src, Message &dest);

public:
    // virgin or adapted message being worked on
    Header *header;   // parsed HTTP status/request line and headers

    /// Copy of header->body_pipe, in case somebody moves the original.
    /// TODO: Find and fix the code that moves (if any) and remove this.
    BodyPipePointer body_pipe;

private:
    Message(const Message &); // not implemented
    Message &operator =(const Message &); // not implemented
};

} // namespace Adaptation;

// TODO: replace ICAPInOut with Adaptation::Message (adding one for "cause")

#endif /* SQUID_SRC_ADAPTATION_MESSAGE_H */

