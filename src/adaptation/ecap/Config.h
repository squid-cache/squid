
/*
 * $Id$
 *
 */

#ifndef SQUID_ECAP_CONFIG_H
#define SQUID_ECAP_CONFIG_H

#include "adaptation/Config.h"

namespace Adaptation
{
namespace Ecap
{

class Config: public Adaptation::Config
{

public:
    Config();
    ~Config();

    virtual void finalize();

private:
    Config(const Config &); // not implemented
    Config &operator =(const Config &); // not implemented

    virtual Adaptation::ServicePointer createService(const Adaptation::ServiceConfig &cfg);
};

extern Config TheConfig;

} // namespace Ecap
} // namespace Adaptation

#endif /* SQUID_ECAP_CONFIG_H */
