CREATE TABLE `passwd` (
  `user` varchar(32) NOT NULL default '',
  `password` varchar(35) NOT NULL default '',
  `enabled` tinyint(1) NOT NULL default '1',
  `fullname` varchar(60) default NULL,
  `comment` varchar(60) default NULL,
  PRIMARY KEY  (`user`)
);
