
This is the readme.txt file for mswin_check_ad_group 2.0, an external
helper for the External ACL Scheme for Squid.


This helper must be used in with an authentication scheme (tipically 
basic, NTLM or Negotiate) based on Windows Active Directory domain users. 
It reads from the standard input the domain username and a list of groups
and tries to match it against the groups membership of the specified
username.

Two running mode are available:

- Local mode:
membership is checked against machine's local groups, cannot be used when
running on a Domain Controller.

- Active Directory Global mode:
membership is checked against the whole Active Directory Forest of the
machine where Squid is running.

The minimal Windows version needed to run mswin_check_ad_group is
a Windows 2000 SP4 member of an Active Directory Domain.

When running in Active Directory Global mode, all types of Active Directory 
security groups are supported:
- Domain Global
- Domain Local from user's domain
- Universal
and Active Directory group nesting is fully supported.


==============
Program Syntax
==============

mswin_check_ad_group [-D domain][-G][-c][-d][-h]

-D domain specify the default user's domain
-G        start helper in Active Directory Global mode
-c        use case insensitive compare (local mode only)
-d        enable debugging
-h        this message


================
squid.conf usage
================

When running in Active Directory Global mode, the AD Group can be specified using the
following syntax:

1. Plain NT4 Group Name
2. Full NT4 Group Name
3. Active Directory Canonical name

As Example:
1. Proxy-Users
2. MYDOMAIN\Proxy-Users
3. mydomain.local/Groups/Proxy-Users

When using Plain NT4 Group Name, the Group is searched in the user's domain.  

external_acl_type AD_global_group %LOGIN c:/squid/libexec/mswin_check_ad_group.exe -G
external_acl_type NT_local_group %LOGIN c:/squid/libexec/mswin_check_ad_group.exe

acl GProxyUsers external AD_global_group MYDOMAIN\GProxyUsers
acl LProxyUsers external NT_local_group LProxyUsers
acl password proxy_auth REQUIRED

http_access allow password GProxyUsers
http_access allow password LProxyUsers
http_access deny all

In the previous example all validated AD users member of MYDOMAIN\GProxyUsers 
domain group or member of LProxyUsers machine local group are allowed to 
use the cache.

Groups with spaces in name, for example "Domain Users", must be quoted and
the acl data ("Domain Users") must be placed into a separate file included
by specifying "/path/to/file". The previous example will be:

acl ProxyUsers external NT_global_group "c:/squid/etc/DomainUsers"

and the DomainUsers files will contain only the following line:

"Domain Users"

NOTES: 
- When running in Active Directory Global mode, for better performance,
  all Domain Controllers of the Active Directory forest should be configured
  as Global Catalog.
- When running in local mode, the standard group name comparison is case
  sensitive, so group name must be specified with same case as in the
  local SAM database.
  It's possible to enable case insensitive group name comparison (-c),
  but on some not-english locales, the results can be unexpected.
- Native WIN32 NTLM and Basic Helpers must be used without the
  -A & -D switches.

Refer to Squid documentation for the more details on squid.conf.


=======
Testing
=======

I strongly reccomend that mswin_check_ad_group is tested prior to being used in a 
production environment. It may behave differently on different platforms.
To test it, run it from the command line. Enter username and group
pairs separated by a space (username must entered with domain%5cusername
syntax). Press ENTER to get an OK or ERR message.
Make sure pressing <CTRL><D> behaves the same as a carriage return.
Make sure pressing <CTRL><C> aborts the program.

Test that entering no details does not result in an OK or ERR message.
Test that entering an invalid username and group results in an ERR message.
Test that entering an valid username and group results in an OK message.

