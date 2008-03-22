mswin_negotiate_auth.exe

Native Windows Negotiate authenticator for Squid.

=====
Usage
=====

mswin_negotiate_auth [-d] [-v] [-h]

-d enables debugging.
-v enables verbose Negotiate packet debugging.
-h print program usage

This is released under the GNU General Public License

==============
Allowing Users
==============

Users that are allowed to access the web proxy must have the Windows NT
User Rights "logon from the network".

Squid.conf typical minimal required changes:

auth_param negotiate program c:/squid/libexec/mswin_negotiate_auth.exe
auth_param negotiate children 5

acl password proxy_auth REQUIRED

http_access allow password
http_access deny all

Refer to Squid documentation for more details.

Currently Internet Explorer has some problems with ftp:// URLs when handling
internal Squid FTP icons. The following squid.conf ACL works around this:

acl internal_icons urlpath_regex -i /squid-internal-static/icons/

http_access allow our_networks internal_icons <== BEFORE authentication ACL !!!
