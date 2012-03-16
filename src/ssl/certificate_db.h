/*
 * $Id$
 */

#ifndef SQUID_SSL_CERTIFICATE_DB_H
#define SQUID_SSL_CERTIFICATE_DB_H

#include "ssl/gadgets.h"
#if HAVE_STRING
#include <string>
#endif
#if HAVE_OPENSSL_OPENSSLV_H
#include <openssl/opensslv.h>
#endif

namespace Ssl
{
/// Cross platform file locker.
class FileLocker
{
public:
    /// Lock file
    FileLocker(std::string const & aFilename);
    /// Unlock file
    ~FileLocker();
private:
#ifdef _SQUID_MSWIN_
    HANDLE hFile; ///< Windows file handle.
#else
    int fd; ///< Linux file descriptor.
#endif
};

/**
 * Database class for storing SSL certificates and their private keys.
 * A database consist by:
 *     - A disk file to store current serial number
 *     - A disk file to store the current database size
 *     - A disk file which is a normal TXT_DB openSSL database
 *     - A directory under which the certificates and their private keys stored.
 *  The database before used must initialized with CertificateDb::create static method.
 */
class CertificateDb
{
public:
    /// Names of db columns.
    enum Columns {
        cnlType = 0,
        cnlExp_date,
        cnlRev_date,
        cnlSerial,
        cnlFile,
        cnlName,
        cnlNumber
    };

    /// A wrapper for OpenSSL database row of TXT_DB database.
    class Row
    {
    public:
        /// Create row wrapper.
        Row();
        /// Delete all row.
        ~Row();
        void setValue(size_t number, char const * value); ///< Set cell's value in row
        char ** getRow(); ///< Raw row
        void reset(); ///< Abandon row and don't free memory
    private:
        char **row; ///< Raw row
        size_t width; ///< Number of cells in the row
    };

    CertificateDb(std::string const & db_path, size_t aMax_db_size, size_t aFs_block_size);
    /// Find certificate and private key for host name
    bool find(std::string const & host_name, Ssl::X509_Pointer & cert, Ssl::EVP_PKEY_Pointer & pkey);
    /// Save certificate to disk.
    bool addCertAndPrivateKey(Ssl::X509_Pointer & cert, Ssl::EVP_PKEY_Pointer & pkey);
    /// Get a serial number to use for generating a new certificate.
    BIGNUM * getCurrentSerialNumber();
    /// Create and initialize a database  under the  db_path
    static void create(std::string const & db_path, int serial);
    /// Check the database stored under the db_path.
    static void check(std::string const & db_path, size_t max_db_size);
    std::string getSNString() const; ///< Get serial number as string.
    bool IsEnabledDiskStore() const; ///< Check enabled of dist store.
private:
    void load(); ///< Load db from disk.
    void save(); ///< Save db to disk.
    size_t size() const; ///< Get db size on disk in bytes.
    /// Increase db size by the given file size and update size_file
    void addSize(std::string const & filename);
    /// Decrease db size by the given file size and update size_file
    void subSize(std::string const & filename);
    size_t readSize() const; ///< Read size from file size_file
    void writeSize(size_t db_size); ///< Write size to file size_file.
    size_t getFileSize(std::string const & filename); ///< get file size on disk.
    /// Only find certificate in current db and return it.
    bool pure_find(std::string const & host_name, Ssl::X509_Pointer & cert, Ssl::EVP_PKEY_Pointer & pkey);

    bool deleteInvalidCertificate(); ///< Delete invalid certificate.
    bool deleteOldestCertificate(); ///< Delete oldest certificate.
    bool deleteByHostname(std::string const & host); ///< Delete using host name.

    /// Callback hash function for serials. Used to create TXT_DB index of serials.
    static unsigned long index_serial_hash(const char **a);
    /// Callback compare function for serials. Used to create TXT_DB index of serials.
    static int index_serial_cmp(const char **a, const char **b);
    /// Callback hash function for names. Used to create TXT_DB index of names..
    static unsigned long index_name_hash(const char **a);
    /// Callback compare function for  names. Used to create TXT_DB index of names..
    static int index_name_cmp(const char **a, const char **b);

    /// Definitions required by openSSL, to use the index_* functions defined above
    ///with TXT_DB_create_index.
#if OPENSSL_VERSION_NUMBER > 0x10000000L
    static unsigned long index_serial_LHASH_HASH(const void *a) {
        return index_serial_hash((const char **)a);
    }
    static int index_serial_LHASH_COMP(const void *arg1, const void *arg2) {
        return index_serial_cmp((const char **)arg1, (const char **)arg2);
    }
    static unsigned long index_name_LHASH_HASH(const void *a) {
        return index_name_hash((const char **)a);
    }
    static int index_name_LHASH_COMP(const void *arg1, const void *arg2) {
        return index_name_cmp((const char **)arg1, (const char **)arg2);
    }
#else
    static IMPLEMENT_LHASH_HASH_FN(index_serial_hash,const char **)
    static IMPLEMENT_LHASH_COMP_FN(index_serial_cmp,const char **)
    static IMPLEMENT_LHASH_HASH_FN(index_name_hash,const char **)
    static IMPLEMENT_LHASH_COMP_FN(index_name_cmp,const char **)
#endif

    static const std::string serial_file; ///< Base name of the file to store serial number.
    static const std::string db_file; ///< Base name of the database index file.
    static const std::string cert_dir; ///< Base name of the directory to store the certs.
    static const std::string size_file; ///< Base name of the file to store db size.
    /// Min size of disk db. If real size < min_db_size the  db will be disabled.
    static const size_t min_db_size;

    const std::string db_path; ///< The database directory.
    const std::string serial_full; ///< Full path of the file to store serial number.
    const std::string db_full; ///< Full path of the database index file.
    const std::string cert_full; ///< Full path of the directory to store the certs.
    const std::string size_full; ///< Full path of the file to store the db size.

    TXT_DB_Pointer db; ///< Database with certificates info.
    const size_t max_db_size; ///< Max size of db.
    const size_t fs_block_size; ///< File system block size.

    bool enabled_disk_store; ///< The storage on the disk is enabled.
};

} // namespace Ssl
#endif // SQUID_SSL_CERTIFICATE_DB_H
