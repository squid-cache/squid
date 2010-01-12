
From: "Francesco Chemolli" <kinkie@kame.usr.dsi.unimi.it>
Subject: Multiple NT domains authenticator
Date: Fri, 7 Jul 2000 15:37:32 +0200 

This is the multi-domain NTLM authenticator, blissfully undocumented
(but there's a few strategic comments, so that at least the user
is not left alone).

The user is expected to enter his/her credentials as domain\username
or domain/username (in analogy to what M$-Proxy does).

Requires Authen::SMB from CPAN and Samba if you need to perform netbios
queries.

        Francesco 'Kinkie' Chemolli

