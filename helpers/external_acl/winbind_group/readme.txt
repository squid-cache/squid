This is the README file for wb_group, an external
helper fo the External ACL Scheme for Squid based on
Samba Winbindd from Samba 2.2.4 or greater.


This helper must be used in with an authentication scheme, tipically 
basic or NTLM, based on Windows NT/2000 domain users. 
It reads two new line terminated arguments from the standard input
(the domain username and group) and tries to match it against
the domain global groups membership of the specified username.

For Winbindd configuration, look the Squid winbind authenticators
instructions.


==============
Program Syntax
==============

wb_group [-d]

-d enable debug mode


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

Groups with spaces in name must be quoted, for example "Domain Users"

NOTE: the group name comparation is case sensitive, so group name
must be specified with same case as in the NT/2000 Domain.

Refer to Squid documentation for the more details on squid.conf.


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

--
Serassio Guido
squidnt@serassio.it
