This is the README file for wb_group, an external
helper fo the External ACL Scheme for Squid based on
Samba Winbindd from Samba 2.2.4 or greater.


This helper must be used in with an authentication scheme, tipically 
basic or NTLM, based on Windows NT/2000 domain users. 
It reads from the standard input the domain username and a list of groups
and tries to match it against the groups membership of the specified
username.

Before compile or configure it, look at the Squid winbind authenticators
instructions: http://www.squid-cache.org/Doc/FAQ/FAQ-23.html#ss23.5

When used in Windows 2000 domains, permissions compatible with pre-Windows 
2000 servers are required. See the Q257988 Microsoft KB article for more
details.


==============
Program Syntax
==============

wb_group [-c][-d][-h]

-c use case insensitive compare
-d enable debugging
-h this message


================
squid.conf usage
================

external_acl_type NT_global_group %LOGIN /usr/local/squid/libexec/wb_group

acl ProxyUsers external NT_global_group ProxyUsers
acl password proxy_auth REQUIRED

http_access allow password ProxyUsers
http_access deny all

In the previous example all validated NT users member of ProxyUsers Global 
domain group are allowed to use the cache.

Groups name can be specified in both domain-qualified group notation
(DOMAIN\Groupname) or simple group name notation.

Groups with spaces in name, for example "Domain Users", must be quoted and
the acl data ("Domain Users") must be placed into a separate file included
by specifying "/path/to/file". The previous example will be:

acl ProxyUsers external NT_global_group "/usr/local/squid/etc/DomainUsers"

and the DomainUsers files will contain only the following line:

"Domain Users"

NOTE: the standard group name comparation is case sensitive, so group name
must be specified with same case as in the NT/2000 Domain.
It's possible to enable not case sensitive group name comparation (-c),
but on on some non - English locales, the results can be unexpected. 
For details see toupper man page, BUGS section.


=======
Testing
=======

I strongly urge that wb_group is tested prior to being used in a 
production environment. It may behave differently on different platforms.
To test it, run it from the command line. Enter username and group
pairs separated by a space (username must entered with domain\\username
syntax). Press ENTER to get an OK or ERR message.
Make sure pressing <CTRL><D> behaves the same as a carriage return.
Make sure pressing <CTRL><C> aborts the program.

Test that entering no details does not result in an OK or ERR message.
Test that entering an invalid username and group results in an ERR message.
Test that entering an valid username and group results in an OK message.

To check winbind functionality use wbinfo provided with Samba, 
try -t, -g and -r options.

--
Serassio Guido
guido.serassio@acmeconsulting.it
