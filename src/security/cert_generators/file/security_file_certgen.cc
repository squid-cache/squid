/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "debug/Stream.h"
#include "helper/protocol_defines.h"
#include "sbuf/Stream.h"
#include "security/cert_generators/file/certificate_db.h"
#include "ssl/crtd_message.h"
#include "time/gadgets.h"

#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#if HAVE_GETOPT_H
#include <getopt.h>
#endif

/**
 \defgroup ssl_crtd security_file_certgen
 \ingroup ExternalPrograms
 \par
    Because the standard generation of SSL certificates for
    sslBump feature, Squid must use external process to
    actually make these calls. This process generate new ssl
    certificates and worked with ssl certificates disk cache.
    Typically there will be five certificate generator processes
    spawned from Squid. Communication occurs via TCP sockets
    bound to the loopback interface. The class in helper.h are
    primally concerned with starting and stopping the helpers.
    Reading and writing to and from the helpers occurs in the
    \link IPCacheAPI IP\endlink and the dnsservers occurs in
    the \link IPCacheAPI IP\endlink and \link FQDNCacheAPI
    FQDN\endlink cache modules.

 \section ssl_crtdInterface Command Line Interface
 \verbatim
usage: security_file_certgen -hv -s directory -M size -b fs_block_size
    -h                   Help
    -v                   Version
    -s directory         Directory path of SSL storage database.
    -M size              Maximum size of SSL certificate disk storage.
    -b fs_block_size     File system block size in bytes. Need for processing
                         natural size of certificate on disk. Default value is
                         2048 bytes.

    After running write requests in the next format:
    <request code><whitespace><body_len><whitespace><body>
    There are two kind of request now:
    new_certificate 14 host=host.dom
        Create new private key and selfsigned certificate for "host.dom".

    new_certificate xxx host=host.dom
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
        Create new private key and certificate request for "host.dom".
        Sign new request by received certificate and private key.

usage: security_file_certgen -c -s ssl_store_path\n
    -c                   Init ssl db directories and exit.

 \endverbatim
 */

static const char *const B_KBYTES_STR = "KB";
static const char *const B_MBYTES_STR = "MB";
static const char *const B_GBYTES_STR = "GB";
static const char *const B_BYTES_STR = "B";

/**
 * Parse bytes unit. It would be one of the next value: MB, GB, KB or B.
 * This function is caseinsensitive.
 */
static size_t parseBytesUnits(const char * unit)
{
    if (!strncasecmp(unit, B_BYTES_STR, strlen(B_BYTES_STR)) ||
            !strncasecmp(unit, "", strlen(unit)))
        return 1;

    if (!strncasecmp(unit, B_KBYTES_STR, strlen(B_KBYTES_STR)))
        return 1 << 10;

    if (!strncasecmp(unit, B_MBYTES_STR, strlen(B_MBYTES_STR)))
        return 1 << 20;

    if (!strncasecmp(unit, B_GBYTES_STR, strlen(B_GBYTES_STR)))
        return 1 << 30;

    throw TextException(ToSBuf("Unknown bytes unit: ", unit), Here());
}

/// Parse the number of bytes given as <integer><unit> value (e.g., 4MB).
/// \param name the name of the option being parsed
static size_t
parseBytesOptionValue(const char * const name, const char * const value)
{
    // Find number from string beginning.
    char const * number_begin = value;
    char const * number_end = value;

    while ((*number_end >= '0' && *number_end <= '9')) {
        ++number_end;
    }

    if (number_end <= number_begin)
        throw TextException(ToSBuf("expecting a decimal number at the beginning of ", name, " value but got: ", value), Here());

    std::string number(number_begin, number_end - number_begin);
    std::istringstream in(number);
    size_t base = 0;
    if (!(in >> base) || !in.eof())
        throw TextException(ToSBuf("unsupported integer part of ", name, " value: ", number), Here());

    const auto multiplier = parseBytesUnits(number_end);
    static_assert(std::is_unsigned<decltype(multiplier * base)>::value, "no signed overflows");
    const auto product = multiplier * base;
    if (base && multiplier != product / base)
        throw TextException(ToSBuf(name, " size too large: ", value), Here());

    return product;
}

/// Print help using response code.
static void usage()
{
    std::string example_host_name = "host.dom";
    std::string request_string = Ssl::CrtdMessage::param_host + "=" + example_host_name;
    std::stringstream request_string_size_stream;
    request_string_size_stream << request_string.length();
    std::string help_string =
        "usage: security_file_certgen -hv -s directory -M size -b fs_block_size\n"
        "\t-h                   Help\n"
        "\t-v                   Version\n"
        "\t-s directory         Directory path of SSL storage database.\n"
        "\t-M size              Maximum size of SSL certificate disk storage.\n"
        "\t-b fs_block_size     File system block size in bytes. Need for processing\n"
        "\t                     natural size of certificate on disk. Default value is\n"
        "\t                     2048 bytes.\n"
        "\n"
        "After running write requests in the next format:\n"
        "<request code><whitespace><body_len><whitespace><body>\n"
        "There are two kind of request now:\n"
        + Ssl::CrtdMessage::code_new_certificate + " " + request_string_size_stream.str() + " " + request_string + "\n" +
        "\tCreate new private key and selfsigned certificate for \"host.dom\".\n"
        + Ssl::CrtdMessage::code_new_certificate + " xxx " + request_string + "\n" +
        "-----BEGIN CERTIFICATE-----\n"
        "...\n"
        "-----END CERTIFICATE-----\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "...\n"
        "-----END RSA PRIVATE KEY-----\n"
        "\tCreate new private key and certificate request for \"host.dom\"\n"
        "\tSign new request by received certificate and private key.\n"
        "usage: security_file_certgen -c -s ssl_store_path\n"
        "\t-c                   Init ssl db directories and exit.\n";
    std::cerr << help_string << std::endl;
}

/// Process new request message.
static bool processNewRequest(Ssl::CrtdMessage & request_message, std::string const & db_path, size_t max_db_size, size_t fs_block_size)
{
    Ssl::CertificateProperties certProperties;
    request_message.parseRequest(certProperties);

    // TODO: create a DB object only once, instead re-allocating here on every call.
    std::unique_ptr<Ssl::CertificateDb> db;
    if (!db_path.empty())
        db.reset(new Ssl::CertificateDb(db_path, max_db_size, fs_block_size));

    Security::CertPointer cert;
    Security::PrivateKeyPointer pkey;
    Security::CertPointer orig;
    std::string &certKey = Ssl::OnDiskCertificateDbKey(certProperties);

    bool dbFailed = false;
    try {
        if (db)
            db->find(certKey, certProperties.mimicCert, cert, pkey);

    } catch (...) {
        dbFailed = true;
        debugs(83, DBG_IMPORTANT, "ERROR: Database search failure: " << CurrentException <<
               Debug::Extra << "database location: " << db_path);
    }

    if (!cert || !pkey) {
        if (!Ssl::generateSslCertificate(cert, pkey, certProperties))
            throw TextException("Cannot create ssl certificate or private key.", Here());

        try {
            /* XXX: this !dbFailed condition prevents the helper fixing DB issues
               by adding cleanly generated certs. Which is not consistent with other
               data caches used by Squid - they purge broken entries and allow clean
               entries to later try and fix the issue.
               We leave it in place now only to avoid breaking existing installations
               behaviour with version 1.x of the helper.

               TODO: remove the !dbFailed condition when fixing the CertificateDb
                    object lifecycle and formally altering the helper behaviour.
            */
            if (!dbFailed && db && !db->addCertAndPrivateKey(certKey, cert, pkey, certProperties.mimicCert))
                throw TextException("Cannot add certificate to db.", Here());

        } catch (...) {
            dbFailed = true;
            debugs(83, DBG_IMPORTANT, "ERROR: Database update failure: " << CurrentException <<
                   Debug::Extra << "database location: " << db_path);
        }
    }

    std::string bufferToWrite;
    if (!Ssl::writeCertAndPrivateKeyToMemory(cert, pkey, bufferToWrite))
        throw TextException("Cannot write ssl certificate or/and private key to memory.", Here());

    Ssl::CrtdMessage response_message(Ssl::CrtdMessage::REPLY);
    response_message.setCode("OK");
    response_message.setBody(bufferToWrite);

    // Use the '\1' char as end-of-message character
    std::cout << response_message.compose() << '\1' << std::flush;

    return true;
}

/// This is the external security_file_certgen process.
int main(int argc, char *argv[])
{
    try {
        Debug::NameThisHelper("sslcrtd_program");

        size_t max_db_size = 0;
        size_t fs_block_size = 0;
        int8_t c;
        bool create_new_db = false;
        std::string db_path;
        // process options.
        while ((c = getopt(argc, argv, "dchvs:M:b:")) != -1) {
            switch (c) {
            case 'd':
                debug_enabled = 1;
                break;
            case 'b':
                fs_block_size = parseBytesOptionValue("-b", optarg);
                break;
            case 's':
                db_path = optarg;
                break;
            case 'M':
                // use of -M without -s is probably an admin mistake, so make it an error
                if (db_path.empty()) {
                    throw TextException("Error -M option requires an -s parameter be set first.", Here());
                }
                max_db_size = parseBytesOptionValue("-M", optarg);
                break;
            case 'v':
                std::cout << "security_file_certgen version " << VERSION << std::endl;
                exit(EXIT_SUCCESS);
                break;
            case 'c':
                create_new_db = true;
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            default:
                exit(EXIT_FAILURE);
            }
        }

        // when -s is used, -M is required
        if (!db_path.empty() && max_db_size == 0)
            throw TextException("security_file_certgen -s requires an -M parameter", Here());

        if (create_new_db) {
            // when -c is used, -s is required (implying also -M, which is checked above)
            if (db_path.empty())
                throw TextException("security_file_certgen is missing the required parameter. There should be -s and -M parameters when -c is used.", Here());

            std::cout << "Initialization SSL db..." << std::endl;
            Ssl::CertificateDb::Create(db_path);
            std::cout << "Done" << std::endl;
            exit(EXIT_SUCCESS);
        }

        // only do filesystem checks when a path (-s) is given
        if (!db_path.empty()) {
            if (fs_block_size == 0) {
                struct statvfs sfs;

                if (xstatvfs(db_path.c_str(), &sfs)) {
                    fs_block_size = 2048;
                } else {
                    fs_block_size = sfs.f_frsize;
                    // Sanity check; make sure we have a meaningful value.
                    if (fs_block_size < 512)
                        fs_block_size = 2048;
                }
            }
            Ssl::CertificateDb::Check(db_path, max_db_size, fs_block_size);
        }

        // Initialize SSL subsystem
        SQUID_OPENSSL_init_ssl();
        // process request.
        for (;;) {
            char request[HELPER_INPUT_BUFFER];
            Ssl::CrtdMessage request_message(Ssl::CrtdMessage::REQUEST);
            Ssl::CrtdMessage::ParseResult parse_result = Ssl::CrtdMessage::INCOMPLETE;

            while (parse_result == Ssl::CrtdMessage::INCOMPLETE) {
                if (fgets(request, HELPER_INPUT_BUFFER, stdin) == nullptr)
                    exit(EXIT_FAILURE);
                size_t gcount = strlen(request);
                parse_result = request_message.parse(request, gcount);
            }

            if (parse_result == Ssl::CrtdMessage::ERROR) {
                throw TextException("Cannot parse request message.", Here());
            } else if (request_message.getCode() == Ssl::CrtdMessage::code_new_certificate) {
                processNewRequest(request_message, db_path, max_db_size, fs_block_size);
            } else {
                throw TextException(ToSBuf("Unknown request code: \"", request_message.getCode(), "\"."), Here());
            }
            std::cout.flush();
        }
    } catch (...) {
        debugs(83, DBG_CRITICAL, "FATAL: Cannot generate certificates: " << CurrentException);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

