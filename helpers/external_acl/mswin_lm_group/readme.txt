
This is the readme.txt file for mswin_check_lm_group, an external
helper fo the External ACL Scheme for Squid.


This helper must be used in with an authentication scheme, tipically 
basic or NTLM, based on Windows NT/2000 domain users. 
It reads from the standard input the domain username and a list of groups
and tries to match it against the groups membership of the specified
username.


==============
Program Syntax
==============

mswin_check_lm_group [-D domain][-G][-P][-c][-d][-h]

-D domain specify the default user's domain
-G        start helper in Domain Global Group mode
-P        use ONLY PDCs for group validation
-c        use case insensitive compare
-d        enable debugging
-h        this message


================
squid.conf usage
================

external_acl_type NT_global_group %LOGIN c:/squid/libexec/mswin_check_lm_group.exe -G
external_acl_type NT_local_group %LOGIN c:/squid/libexec/mswin_check_lm_group.exe

acl GProxyUsers external NT_global_group GProxyUsers
acl LProxyUsers external NT_local_group LProxyUsers
acl password proxy_auth REQUIRED

http_access allow password GProxyUsers
http_access allow password LProxyUsers
http_access deny all

In the previous example all validated NT users member of GProxyUsers Global 
domain group or member of LProxyUsers machine local group are allowed to 
use the cache.

Groups with spaces in name, for example "Domain Users", must be quoted and
the acl data ("Domain Users") must be placed into a separate file included
by specifying "/path/to/file". The previous example will be:

acl ProxyUsers external NT_global_group "c:/squid/etc/DomainUsers"

and the DomainUsers files will contain only the following line:

"Domain Users"

NOTES: 
- The standard group name comparation is case sensitive, so group name
  must be specified with same case as in the NT/2000 Domain.
  It's possible to enable not case sensitive group name comparation (-c),
  but on on some non - English locales, the results can be unexpected.
- Native WIN32 NTLM and Basic Helpers must be used without the
  -A & -D switches.

Refer to Squid documentation for the more details on squid.conf.


=======
Testing
=======

I strongly reccomend that mswin_check_lm_group is tested prior to being used in a 
production environment. It may behave differently on different platforms.
To test it, run it from the command line. Enter username and group
pairs separated by a space (username must entered with domain\\username
syntax). Press ENTER to get an OK or ERR message.
Make sure pressing <CTRL><D> behaves the same as a carriage return.
Make sure pressing <CTRL><C> aborts the program.

Test that entering no details does not result in an OK or ERR message.
Test that entering an invalid username and group results in an ERR message.
Test that entering an valid username and group results in an OK message.

