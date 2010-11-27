#ifndef SQUID_SRC_LOG_CONFIG_H
#define SQUID_SRC_LOG_CONFIG_H

namespace Log
{

class LogConfig
{
public:
    char *logfile_daemon;
};

extern LogConfig TheConfig;

} // namespace Log

#endif
