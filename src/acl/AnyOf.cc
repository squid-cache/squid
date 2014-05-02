#include "squid.h"
#include "acl/AnyOf.h"

char const *
Acl::AnyOf::typeString() const
{
    return "any-of";
}

ACL *
Acl::AnyOf::clone() const
{
    return new AnyOf;
}

// called once per "acl name any-of name1 name2 ...." line
// but since multiple lines are ORed, the line boundary does not matter,
// so we flatten the tree into one line/level here to minimize overheads
void
Acl::AnyOf::parse()
{
    lineParse();
}
