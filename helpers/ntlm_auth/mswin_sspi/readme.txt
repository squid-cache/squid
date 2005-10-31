mswin_ntlm_auth.exe

Native Windows NTLM/NTLMv2 authenticator for Squid with
automatic support for NTLM NEGOTIATE packets.

=====
Usage
=====

mswin_ntlm_auth [-d] [-v] [-A|D LocalUserGroup] [-h]

-d enables debugging.
-v enables verbose NTLM packet debugging.
-A specify a Windows Local Group name allowed to authenticate.
-D specify a Windows Local Group name not allowed to authenticate.
-h print program usage

This is released under the GNU General Public License

==============
Allowing Users
==============

Users that are allowed to access the web proxy must have the Windows NT
User Rights "logon from the network".
Optionally the authenticator can verify the NT LOCAL group membership of 
the user against the User Group specified in the Authenticator's command
line. 
This can be accomplished creating a local user group on the NT machine,
grant the privilege, and adding users to it, it works only with MACHINE
Local Groups, not Domain Local Groups.
Better group checking is available with External Acl, see mswin_check_group
documentation.

The use of NTLM NEGOTIATE packet allow full NTLM/NTLMv2 support, but
Squid too must be configured to use NTLM NEGOTIATE, see squid.conf.

Squid.conf typical minimal required changes:

auth_param ntlm program c:/squid/libexec/mswin_ntlm_auth.exe
auth_param ntlm children 5
auth_param ntlm max_challenge_reuses 0
auth_param ntlm max_challenge_lifetime 2 minutes
auth_param ntlm use_ntlm_negotiate on

acl password proxy_auth REQUIRED

http_access allow password
http_access deny all

When using "use_ntlm_negotiate on" 
max_challenge_reuses and max_challenge_lifetime parameters must be specified
but they are are ignored.

Refer to Squid documentation for more details.

Currently Internet Explorer has some problems with ftp:// URLs when handling
internal Squid FTP icons. The following squid.conf ACL works around this:

acl internal_icons urlpath_regex -i /squid-internal-static/icons/

http_access allow our_networks internal_icons <== BEFORE authentication ACL !!!


===============
Contact details
===============

To contact the maintainer of this package, e-mail on squidnt@acmeconsulting.it.
The latest version may be found on http://www.acmeconsulting.it/SquidNT.htm.
