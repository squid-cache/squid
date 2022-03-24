/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SSL_CERTIFICATE_DB_H
#define SQUID_SSL_CERTIFICATE_DB_H

#include "ssl/gadgets.h"

#include <string>

namespace Ssl
{
/// maintains an exclusive blocking file-based lock
class Lock
{
public:
    explicit Lock(std::string const &filename); ///<  creates an unlocked lock
    ~Lock(); ///<  releases the lock if it is locked
    void lock(); ///<  locks the lock, may block
    void unlock(); ///<  unlocks locked lock or throws
    bool locked() const; ///<  whether our lock is locked
    const char *name() const { return filename.c_str(); }
private:
    std::string filename;
#if _SQUID_WINDOWS_
    HANDLE hFile; ///< Windows file handle.
#else
    int fd; ///< Linux file descriptor.
#endif
};

/// an exception-safe way to obtain and release a lock
class Locker
{
public:
    /// locks the lock if the lock was unlocked
    Locker(Lock &lock, const char  *aFileName, int lineNo);
    /// unlocks the lock if it was locked by us
    ~Locker();
private:
    bool weLocked; ///<  whether we locked the lock
    Lock &lock; ///<  the lock we are operating on
    const std::string fileName; ///<  where the lock was needed
    const int lineNo; ///<  where the lock was needed
};

/// convenience macro to pass source code location to Locker and others
#define Here __FILE__, __LINE__

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
        cnlKey = 0, //< The key to use for storing/retrieving entries from DB.
        cnlExp_date,
        cnlRev_date,
        cnlSerial,
        cnlName,
        cnlNumber
    };

    /// A wrapper for OpenSSL database row of TXT_DB database.
    class Row
    {
    public:
        /// Create row wrapper.
        Row();
        ///Create row wrapper for row with width items
        Row(char **row, size_t width);
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
    /// finds matching generated certificate and its private key
    bool find(std::string const & key,  const Security::CertPointer &expectedOrig, Security::CertPointer & cert, Security::PrivateKeyPointer & pkey);
    /// Delete a certificate from database
    bool purgeCert(std::string const & key);
    /// Save certificate to disk.
    bool addCertAndPrivateKey(std::string const & useKey, const Security::CertPointer & cert, const Security::PrivateKeyPointer & pkey, const Security::CertPointer &orig);

    /// Create and initialize a database  under the  db_path
    static void Create(std::string const & db_path);
    /// Check the database stored under the db_path.
    static void Check(std::string const & db_path, size_t max_db_size, size_t fs_block_size);
private:
    void load(); ///< Load db from disk.
    void save(); ///< Save db to disk.
    size_t size(); ///< Get db size on disk in bytes.
    /// Increase db size by the given file size and update size_file
    void addSize(std::string const & filename);
    /// Decrease db size by the given file size and update size_file
    void subSize(std::string const & filename);
    size_t readSize(); ///< Read size from file size_file
    void writeSize(size_t db_size); ///< Write size to file size_file.
    size_t getFileSize(std::string const & filename); ///< get file size on disk.
    size_t rebuildSize(); ///< Rebuild size_file
    /// Only find certificate in current db and return it.
    bool pure_find(std::string const & key, const Security::CertPointer & expectedOrig, Security::CertPointer & cert, Security::PrivateKeyPointer & pkey);

    void deleteRow(const char **row, int rowIndex); ///< Delete a row from TXT_DB
    bool deleteInvalidCertificate(); ///< Delete invalid certificate.
    bool deleteOldestCertificate(); ///< Delete oldest certificate.
    bool deleteByKey(std::string const & key); ///< Delete using key.
    bool hasRows() const; ///< Whether the TXT_DB has stored items.

    /// stores the db entry into a file
    static bool WriteEntry(const std::string &filename, const Security::CertPointer & cert, const Security::PrivateKeyPointer & pkey, const Security::CertPointer &orig);

    /// loads a db entry from the file
    static bool ReadEntry(std::string filename, Security::CertPointer & cert, Security::PrivateKeyPointer & pkey, Security::CertPointer &orig);

    /// Removes the first matching row from TXT_DB. Ignores failures.
    static void sq_TXT_DB_delete(TXT_DB *db, const char **row);
    /// Remove the row on position idx from TXT_DB. Ignores failures.
    static void sq_TXT_DB_delete_row(TXT_DB *db, int idx);

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
#if SQUID_USE_SSLLHASH_HACK
    static unsigned long index_serial_hash_LHASH_HASH(const void *a) {
        return index_serial_hash((const char **)a);
    }
    static int index_serial_cmp_LHASH_COMP(const void *arg1, const void *arg2) {
        return index_serial_cmp((const char **)arg1, (const char **)arg2);
    }
    static unsigned long index_name_hash_LHASH_HASH(const void *a) {
        return index_name_hash((const char **)a);
    }
    static int index_name_cmp_LHASH_COMP(const void *arg1, const void *arg2) {
        return index_name_cmp((const char **)arg1, (const char **)arg2);
    }
#else
    static IMPLEMENT_LHASH_HASH_FN(index_serial_hash,const char **)
    static IMPLEMENT_LHASH_COMP_FN(index_serial_cmp,const char **)
    static IMPLEMENT_LHASH_HASH_FN(index_name_hash,const char **)
    static IMPLEMENT_LHASH_COMP_FN(index_name_cmp,const char **)
#endif

    static const std::string db_file; ///< Base name of the database index file.
    static const std::string cert_dir; ///< Base name of the directory to store the certs.
    static const std::string size_file; ///< Base name of the file to store db size.
    /// Min size of disk db. If real size < min_db_size the  db will be disabled.
    static const size_t min_db_size;

    const std::string db_path; ///< The database directory.
    const std::string db_full; ///< Full path of the database index file.
    const std::string cert_full; ///< Full path of the directory to store the certs.
    const std::string size_full; ///< Full path of the file to store the db size.

    TXT_DB_Pointer db; ///< Database with certificates info.
    const size_t max_db_size; ///< Max size of db.
    const size_t fs_block_size; ///< File system block size.
    mutable Lock dbLock;  ///< protects the database file
};

} // namespace Ssl
#endif // SQUID_SSL_CERTIFICATE_DB_H

