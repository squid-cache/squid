/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "comm/Connection.h"
#include "errorpage.h"
#include "security/EncryptorAnswer.h"

Security::EncryptorAnswer::~EncryptorAnswer()
{
    delete error.get();
}

std::ostream &
Security::operator <<(std::ostream &os, const Security::EncryptorAnswer &answer)
{
    return os << answer.conn << ", " << answer.error;
}

