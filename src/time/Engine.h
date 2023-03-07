/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_TIME_ENGINE_H
#define SQUID__SRC_TIME_ENGINE_H

namespace Time {

/// event class for doing synthetic time etc
class Engine
{
public:
    virtual ~Engine() {}

    // tick the clock - update from the OS or other time source
    virtual void tick();
};

} // namespace Time

#endif /* SQUID__SRC_TIME_ENGINE_H */

