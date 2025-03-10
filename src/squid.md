---
title: squid
section: 8
---
# NAME

**squid** - HTTP web proxy caching server

# SYNOPSIS

**squid** [-sCFNRSXY] [-d level] [-\-foreground] [-l facility] [-f file] [-[au] port] [-k signal] [-n service]

**squid** -[hv]

**squid** -n service -i [-sX] [-d level] [-\-foreground] [-l facility]

**squid** -n service -r [-sX] [-d level] [-\-foreground] [-l facility]

**squid** -n service -O command [-s] [-d level] [-\-foreground] [-l facility]

**squid** -z [-NS] [-sX] [-d level] [-\-foreground] [-l facility] [-f file] [-n service]

# DESCRIPTION

**squid** is a high-performance proxy caching server for web
clients, supporting FTP, ICAP, ICP, HTCP and HTTP data objects.
Unlike traditional caching software, Squid handles all requests
in a single, non-blocking process.

Squid keeps meta data and especially hot objects cached in RAM,
caches DNS lookups, supports non-blocking DNS lookups, and
implements negative caching of failed requests.

Squid supports TLS, extensive access controls, and full request
logging.  By using the lightweight Internet Cache Protocols ICP,
HTCP or CARP, Squid caches can be arranged in a hierarchy or
mesh for additional bandwidth savings.

Squid consists of a main server program **squid**, some optional
programs for custom processing and authentication, and some
management and client tools.  When squid starts up, it spawns a
configurable number of helper processes, each of which can
perform parallel lookups.  This reduces the amount of time the
cache waits for results.

Squid is derived from the ARPA funded Harvest Project.

This manual page only lists the command line arguments. For
details on how to configure Squid see the file
**@SYSCONFDIR@/squid.conf.documented**, the Squid
[wiki FAQ](https://wiki.squid-cache.org/) and examples, or the
[configuration manual](http://www.squid-cache.org/Doc/config/).

# OPTIONS

-a port
> Specify HTTP port number where Squid should listen for
  requests, in addition to any
  [http_port](http://www.squid-cache.org/Doc/config/html_port/)
  in **@SYSCONFDIR@/squid.conf**

-C
> Do not catch fatal signals.

-d level
> Write debugging to stderr also.

-f file
> Use the given file instead of @SYSCONFDIR@/squid.conf .
  If the file name starts with a **!** or **|** then it is
  assumed to be an external command or command line. Can for
  example be used to pre\-process the configuration before it is
  being read by Squid. To facilitate this Squid also understands
  the common #line notion to indicate the real source file.

-F
> Don't serve any requests until store is rebuilt.

-h
> Print help message.

-i
> Install as a Windows Service (see **"-n"** option).

-k [ reconfigure | rotate | shutdown | interrupt | kill | debug | check | parse ]
> Parse configuration file, then send signal to running copy
  (except **"-k parse"**) and exit.

-l facility
> Use specified syslog facility. Implies **"-s"**

-n name
> Specify Windows Service name to use for service operations.
  The default is **"Squid"**

-N
> No daemon mode.

-\-foreground
> Parent process does not exit until its children have finished.
  It has no effect with **"-N"** which does not fork/exit at
  startup.

-\-kid roleID
> Play a given SMP kid process role, with a given ID.
  **Do not use this option**. It is meant for the master process
  use only.

-O options
> Set Windows Service Command line options in Registry.

-r
> Remove a Windows Service (see **"-n"** option).

-R
> Do not set **REUSEADDR** on port.

-s
> Enable logging to syslog. Also configurable in
  **@SYSCONFDIR@/squid.conf**

-S
> Double-check swap during rebuild.

-u port
> Specify ICP port number.

-v
> Print version and build details.

-X
> Force full debugging.

-Y
> Only return **UDP_HIT** or **UDP_MISS_NOFETCH** during fast
  reload.

-z
> Create missing swap directories and other missing
  [cache_dir](http://www.squid-cache.org/Doc/config/cache_dir/)
  structures, then exit.
> All cache_dir types create the configured top-level directory
  if it is missing. Other actions are type-specific.
> This option does not enable validation of any present swap
  structures. Its focus is on creation of missing pieces.
> If nothing is missing, **squid -z** just exits.
> If you suspect cache_dir corruption, you must delete the
  top-level cache_dir directory before running **squid -z**.
> By default, **squid -z** runs in daemon mode so that
  configuration macros and other SMP features work as expected,
  returning control to the caller before cache_dirs are fully
  initialized.
> If run from init scripts or daemon managers, the caller often
  needs to wait for the initialization to complete before
  proceeding further.
> Use **"-\-foreground"** option to prevent premature exits.
> Use **-N** option to disable daemon mode.

# FILES

Squid configuration files located in @SYSCONFDIR@/:

squid.conf
> The main configuration file.
> You must initially make changes to this file for **squid** to
  work.

squid.conf.default
> Reference copy of the configuration file. Always kept up to
  date with the version of Squid you are using.
> Use this to look up the default configuration settings and
  syntax after upgrading.

squid.conf.documented
> Reference copy of the configuration file. Always kept up to
  date with the version of Squid you are using.
> Use this to read the documentation for configuration options
  available in your build of Squid.
> The [online configuration manual](http://www.squid-cache.org/Doc/config/)
  is also available for a full reference of options.

errorpage.css
> CSS Stylesheet to control display of generated error pages.
> Use this to set any company branding you need, it will apply
  to every language Squid provides error pages for.

Some files also located elsewhere:

mime_table @DEFAULT_MIME_TABLE@
> MIME type mappings for FTP gatewaying
> Can be configured with the
  [mime_table directive](http://www.squid-cache.org/Doc/config/mime_table/)

error_directory @DEFAULT_ERROR_DIR@
> Location of Squid error pages and templates.

# AUTHOR

Squid was written over many years by a changing team of
developers and maintained in turn by
 *Duane Wessels <duane@squid-cache.org>*,
 *Henrik Nordstrom <hno@squid-cache.org>*,
 *Amos Jeffries <amosjeffries@squid-cache.org>*,
 *Francesco Chemolli <kinkie@squid-cache.org>*

With contributions from many others in the Squid community.

See CONTRIBUTORS for a full list of individuals who contributed
code.

See CREDITS for a list of major code contributing copyright
holders.

# COPYRIGHT

 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.

# QUESTIONS

Questions on the usage of this program can be sent to the
*Squid Users* mailing list <squid-users@lists.squid-cache.org>.

# REPORTING BUGS

Bug reports need to be made in English.
See https://wiki.squid-cache.org/SquidFaq/BugReporting for
details of what you need to include with your bug report.

Report bugs or bug fixes using https://bugs.squid-cache.org/.

Report serious security bugs to
*Squid Bugs* mailing list <squid-bugs@lists.squid-cache.org>.

Report ideas for new improvements to the
*Squid Developers* mailing list <squid-dev@lists.squid-cache.org>.

# SEE ALSO

The [FAQ wiki](https://wiki.squid-cache.org/SquidFaq)

The [Configuration Manual](http://www.squid-cache.org/Doc/config/)

The [Helper Manuals](http://www.squid-cache.org/Doc/man/)
