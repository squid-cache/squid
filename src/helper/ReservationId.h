/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HELPER_RESERVATIONID_H
#define _SQUID_SRC_HELPER_RESERVATIONID_H

#include <ostream>

namespace Helper
{
/// a (temporary) lock on a (stateful) helper channel
class ReservationId
{
public:
    static ReservationId Next();

    bool reserved() const { return id > 0; }

    explicit operator bool() const { return reserved(); }
    bool operator !() const { return !reserved(); }
    bool operator ==(const Helper::ReservationId &other) const { return id == other.id; }
    bool operator !=(const Helper::ReservationId &other) const { return !(*this == other); }

    void clear() { id = 0; }
    uint64_t value() const {return id;}

    /// dumps the reservation info for debugging
    std::ostream &print(std::ostream &os) const;

private:
    uint64_t id = 0; ///< uniquely identifies this reservation
};

}; // namespace Helper

inline std::ostream &
operator <<(std::ostream &os, const Helper::ReservationId &id)
{
    return id.print(os);
}

namespace std {
/// default hash functor to support std::unordered_map<HelperReservationId, *>
template <>
struct hash<Helper::ReservationId>
{
    typedef Helper::ReservationId argument_type;
    typedef std::size_t result_type;
    result_type operator()(const argument_type &reservation) const noexcept
    {
        std::hash<uint64_t> aHash;
        return aHash(reservation.value());
    }
};
}

#endif

