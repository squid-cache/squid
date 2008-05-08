
/*
 * $Id$
 */

#ifndef SQUID__ADAPTATION__MESSAGE_H
#define SQUID__ADAPTATION__MESSAGE_H

class HttpMsg;
class BodyPipe;
template <class C>
class RefCount;
typedef RefCount<BodyPipe> BodyPipePointer;

namespace Adaptation {

// Manages the header and the body of an HTTP message being worked on.
// Adaptation transactions use this class for virgin and adapted HTTP messages.
class Message
{

public:
    typedef HttpMsg Header;

    Message();
    Message(Header *aHeader);
    ~Message();

    void clear();
    void set(Header *aHeader);

	void copyTo(Message &dest);

public:
    // virgin or adapted message being worked on
    Header *header;   // parsed HTTP status/request line and headers

	// Copy of header->body_pipe, in case somebody moves the original.
	BodyPipePointer body_pipe;

private:
    Message(const Message &); // not implemented
    Message &operator =(const Message &); // not implemented
};

} // namespace Adaptation;

// TODO: replace ICAPInOut with Adaptation::Message (adding one for "cause")

#endif /* SQUID__ADAPTATION__MESSAGE_H */
