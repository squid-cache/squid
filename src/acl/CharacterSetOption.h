/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_CHARACTERSETOPTION_H
#define SQUID_SRC_ACL_CHARACTERSETOPTION_H

#include "acl/Options.h"
#include "base/CharacterSet.h"
#include "sbuf/SBuf.h"

namespace Acl {

typedef OptionValue<CharacterSet> CharacterSetOptionValue;

/* TypedOption<CharacterSetOptionValue> specializations */

template <>
inline
void
TypedOption<CharacterSetOptionValue>::import(const SBuf &rawValue) const
{
    SBuf chars = rawValue; // because c_str() is not constant
    recipient_->value = CharacterSet(__FILE__, chars.c_str());
}

template <>
inline
void
TypedOption<CharacterSetOptionValue>::print(std::ostream &os) const
{
    recipient_->value.printChars(os); // TODO: Quote if needed.
}

/// option value to configure one or more characters (e.g., -m=",;")
class CharacterSetOption: public TypedOption<CharacterSetOptionValue>
{
public:
    typedef TypedOption<CharacterSetOptionValue> Parent;
    explicit CharacterSetOption(const char *name): Parent(name, nullptr, valueOptional) {}
};

} // namespace Acl

#endif /* SQUID_SRC_ACL_CHARACTERSETOPTION_H */

