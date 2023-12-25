/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "helper/ReservationId.h"

Helper::ReservationId
Helper::ReservationId::Next()
{
    static uint64_t Ids = 0;
    Helper::ReservationId reservation;
    reservation.id = ++Ids;
    return reservation;
}

std::ostream &
Helper::ReservationId::print(std::ostream &os) const
{
    return os << "hlpRes" << id;
}

