/*
 * $Id: ACLCertificate.cc,v 1.2 2003/03/04 01:40:25 robertc Exp $
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "ACLCertificate.h"
#include "ACLChecklist.h"
#include "ACLCertificateData.h"
#include "fde.h"
#include "client_side.h"

ACL::Prototype ACLCertificate::UserRegistryProtoype(&ACLCertificate::UserRegistryEntry_, "user_cert");
ACLStrategised<SSL *> ACLCertificate::UserRegistryEntry_(new ACLCertificateData (sslGetUserAttribute), ACLCertificateStrategy::Instance(), "user_cert");
ACL::Prototype ACLCertificate::CARegistryProtoype(&ACLCertificate::CARegistryEntry_, "ca_cert");
ACLStrategised<SSL *> ACLCertificate::CARegistryEntry_(new ACLCertificateData (sslGetCAAttribute), ACLCertificateStrategy::Instance(), "ca_cert");

int
ACLCertificateStrategy::match (ACLData<MatchType> * &data, ACLChecklist *checklist)
{
    SSL *ssl = fd_table[checklist->conn()->fd].ssl;
    return data->match (ssl);
}

ACLCertificateStrategy *
ACLCertificateStrategy::Instance()
{
    return &Instance_;
}

ACLCertificateStrategy ACLCertificateStrategy::Instance_;
