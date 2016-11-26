/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "helper/protocol_defines.h"
#include "security/cert_generators/file/certificate_db.h"
#include "ssl/crtd_message.h"

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
usage: security_file_certgen -hv -s ssl_storage_path -M storage_max_size
    -h                   Help
    -v                   Version
    -s ssl_storage_path  Path to specific disk storage of ssl server
                         certificates.
    -M storage_max_size  max size of ssl certificates storage.
    -b fs_block_size     File system block size in bytes. Need for processing
                         natural size of certificate on disk. Default value is
                         2048 bytes."

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

/// Get current time.
time_t getCurrentTime(void)
{
    struct timeval current_time;
#if GETTIMEOFDAY_NO_TZP
    gettimeofday(&current_time);
#else
    gettimeofday(&current_time, NULL);
#endif
    return current_time.tv_sec;
}

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

    std::cerr << "WARNING: Unknown bytes unit '" << unit << "'" << std::endl;

    return 0;
}

/// Parse uninterrapted string of bytes value. It looks like "4MB".
static bool parseBytesOptionValue(size_t * bptr, char const * value)
{
    // Find number from string beginning.
    char const * number_begin = value;
    char const * number_end = value;

    while ((*number_end >= '0' && *number_end <= '9')) {
        ++number_end;
    }

    std::string number(number_begin, number_end - number_begin);
    std::istringstream in(number);
    int d = 0;
    if (!(in >> d))
        return false;

    int m;
    if ((m = parseBytesUnits(number_end)) == 0) {
        return false;
    }

    *bptr = static_cast<size_t>(m * d);
    if (static_cast<long>(*bptr * 2) != m * d * 2)
        return false;

    return true;
}

/// Print help using response code.
static void usage()
{
    std::string example_host_name = "host.dom";
    std::string request_string = Ssl::CrtdMessage::param_host + "=" + example_host_name;
    std::stringstream request_string_size_stream;
    request_string_size_stream << request_string.length();
    std::string help_string =
        "usage: security_file_certgen -hv -s ssl_storage_path -M storage_max_size\n"
        "\t-h                   Help\n"
        "\t-v                   Version\n"
        "\t-s ssl_storage_path  Path to specific disk storage of ssl server\n"
        "\t                     certificates.\n"
        "\t-M storage_max_size  max size of ssl certificates storage.\n"
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
    std::string error;
    if (!request_message.parseRequest(certProperties, error))
        throw std::runtime_error("Error while parsing the crtd request: " + error);

    Ssl::CertificateDb db(db_path, max_db_size, fs_block_size);

    Security::CertPointer cert;
    Ssl::EVP_PKEY_Pointer pkey;
    std::string &cert_subject = certProperties.dbKey();

    bool dbFailed = false;
    try {
        db.find(cert_subject, cert, pkey);
    } catch (std::runtime_error &err) {
        dbFailed = true;
        error = err.what();
    }

    if (cert) {
        if (!Ssl::certificateMatchesProperties(cert.get(), certProperties)) {
            // The certificate changed (renewed or other reason).
            // Generete a new one with the updated fields.
            cert.reset();
            pkey.reset();
            db.purgeCert(cert_subject);
        }
    }

    if (!cert || !pkey) {
        if (!Ssl::generateSslCertificate(cert, pkey, certProperties))
            throw std::runtime_error("Cannot create ssl certificate or private key.");

        if (!dbFailed && db.IsEnabledDiskStore()) {
            try {
                if (!db.addCertAndPrivateKey(cert, pkey, cert_subject)) {
                    dbFailed = true;
                    error = "Cannot add certificate to db.";
                }
            } catch (const std::runtime_error &err) {
                dbFailed = true;
                error = err.what();
            }
        }
    }

    if (dbFailed)
        std::cerr << "security_file_certgen helper database '" << db_path  << "' failed: " << error << std::endl;

    std::string bufferToWrite;
    if (!Ssl::writeCertAndPrivateKeyToMemory(cert, pkey, bufferToWrite))
        throw std::runtime_error("Cannot write ssl certificate or/and private key to memory.");

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
        size_t max_db_size = 0;
        size_t fs_block_size = 0;
        int8_t c;
        bool create_new_db = false;
        std::string db_path;
        // process options.
        while ((c = getopt(argc, argv, "dcghvs:M:b:n:")) != -1) {
            switch (c) {
            case 'd':
                debug_enabled = 1;
                break;
            case 'b':
                if (!parseBytesOptionValue(&fs_block_size, optarg)) {
                    throw std::runtime_error("Error when parsing -b options value");
                }
                break;
            case 's':
                db_path = optarg;
                break;
            case 'M':
                if (!parseBytesOptionValue(&max_db_size, optarg)) {
                    throw std::runtime_error("Error when parsing -M options value");
                }
                break;
            case 'v':
                std::cout << "security_file_certgen version " << VERSION << std::endl;
                exit(0);
                break;
            case 'c':
                create_new_db = true;
                break;
            case 'h':
                usage();
                exit(0);
            default:
                exit(0);
            }
        }

        if (create_new_db) {
            std::cout << "Initialization SSL db..." << std::endl;
            Ssl::CertificateDb::create(db_path);
            std::cout << "Done" << std::endl;
            exit(0);
        }

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

        {
            Ssl::CertificateDb::check(db_path, max_db_size, fs_block_size);
        }
        // Initialize SSL subsystem
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();
        // process request.
        for (;;) {
            char request[HELPER_INPUT_BUFFER];
            Ssl::CrtdMessage request_message(Ssl::CrtdMessage::REQUEST);
            Ssl::CrtdMessage::ParseResult parse_result = Ssl::CrtdMessage::INCOMPLETE;

            while (parse_result == Ssl::CrtdMessage::INCOMPLETE) {
                if (fgets(request, HELPER_INPUT_BUFFER, stdin) == NULL)
                    return 1;
                size_t gcount = strlen(request);
                parse_result = request_message.parse(request, gcount);
            }

            if (parse_result == Ssl::CrtdMessage::ERROR) {
                throw std::runtime_error("Cannot parse request message.");
            } else if (request_message.getCode() == Ssl::CrtdMessage::code_new_certificate) {
                processNewRequest(request_message, db_path, max_db_size, fs_block_size);
            } else {
                throw std::runtime_error("Unknown request code: \"" + request_message.getCode() + "\".");
            }
            std::cout.flush();
        }
    } catch (std::runtime_error & error) {
        std::cerr << argv[0] << ": " << error.what() << std::endl;
        return 0;
    }
    return 0;
}

