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
