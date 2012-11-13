#ifndef SQUID_FATAL_H
#define SQUID_FATAL_H

void fatal(const char *message);
void fatalf(const char *fmt,...) PRINTF_FORMAT_ARG1;
void fatal_dump(const char *message);

#endif /* SQUID_FATAL_H */
