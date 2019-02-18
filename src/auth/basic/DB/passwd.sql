## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

CREATE TABLE `passwd` (
  `user` varchar(32) NOT NULL default '',
  `password` varchar(35) NOT NULL default '',
  `enabled` tinyint(1) NOT NULL default '1',
  `fullname` varchar(60) default NULL,
  `comment` varchar(60) default NULL,
  PRIMARY KEY  (`user`)
);
