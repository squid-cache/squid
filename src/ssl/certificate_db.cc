/*
 * $Id$
 */

#include "config.h"
#include "util.h"
#include "ssl/certificate_db.h"
#if HAVE_FSTREAM
#include <fstream>
#endif
#if HAVE_STDEXCEPT
#include <stdexcept>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

Ssl::FileLocker::FileLocker(std::string const & filename)
        :    fd(-1)
{
#if _SQUID_MSWIN_
    hFile = CreateFile(TEXT(filename.c_str()), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
        LockFile(hFile, 0, 0, 1, 0);
#else
    fd = open(filename.c_str(), 0);
    if (fd != -1)
        flock(fd, LOCK_EX);
#endif
}

Ssl::FileLocker::~FileLocker()
{
#ifdef _SQUID_MSWIN_
    if (hFile != INVALID_HANDLE_VALUE) {
        UnlockFile(hFile, 0, 0, 1, 0);
        CloseHandle(hFile);
    }
#else
    if (fd != -1) {
        flock(fd, LOCK_UN);
        close(fd);
    }
#endif
}

Ssl::CertificateDb::Row::Row()
        :   width(cnlNumber)
{
    row = new char *[width + 1];
    for (size_t i = 0; i < width + 1; i++)
        row[i] = NULL;
}

Ssl::CertificateDb::Row::~Row()
{
    if (row) {
        for (size_t i = 0; i < width + 1; i++) {
            delete[](row[i]);
        }
        delete[](row);
    }
}

void Ssl::CertificateDb::Row::reset()
{
    row = NULL;
}

void Ssl::CertificateDb::Row::setValue(size_t cell, char const * value)
{
    assert(cell < width);
    if (row[cell]) {
        free(row[cell]);
    }
    if (value) {
        row[cell] = static_cast<char *>(xmalloc(sizeof(char) * (strlen(value) + 1)));
        memcpy(row[cell], value, sizeof(char) * (strlen(value) + 1));
    } else
        row[cell] = NULL;
}

char ** Ssl::CertificateDb::Row::getRow()
{
    return row;
}

unsigned long Ssl::CertificateDb::index_serial_hash(const char **a)
{
    const char *n = a[Ssl::CertificateDb::cnlSerial];
    while (*n == '0') n++;
    return lh_strhash(n);
}

int Ssl::CertificateDb::index_serial_cmp(const char **a, const char **b)
{
    const char *aa, *bb;
    for (aa = a[Ssl::CertificateDb::cnlSerial]; *aa == '0'; aa++);
    for (bb = b[Ssl::CertificateDb::cnlSerial]; *bb == '0'; bb++);
    return strcmp(aa, bb);
}

unsigned long Ssl::CertificateDb::index_name_hash(const char **a)
{
    return(lh_strhash(a[Ssl::CertificateDb::cnlName]));
}

int Ssl::CertificateDb::index_name_cmp(const char **a, const char **b)
{
    return(strcmp(a[Ssl::CertificateDb::cnlName], b[CertificateDb::cnlName]));
}

const std::string Ssl::CertificateDb::serial_file("serial");
const std::string Ssl::CertificateDb::db_file("index.txt");
const std::string Ssl::CertificateDb::cert_dir("certs");
const std::string Ssl::CertificateDb::size_file("size");
const size_t Ssl::CertificateDb::min_db_size(4096);

Ssl::CertificateDb::CertificateDb(std::string const & aDb_path, size_t aMax_db_size, size_t aFs_block_size)
        :  db_path(aDb_path),
        serial_full(aDb_path + "/" + serial_file),
        db_full(aDb_path + "/" + db_file),
        cert_full(aDb_path + "/" + cert_dir),
        size_full(aDb_path + "/" + size_file),
        db(NULL),
        max_db_size(aMax_db_size),
        fs_block_size(aFs_block_size),
        enabled_disk_store(true)
{
    if (db_path.empty() && !max_db_size)
        enabled_disk_store = false;
    else if ((db_path.empty() && max_db_size) || (!db_path.empty() && !max_db_size))
        throw std::runtime_error("ssl_crtd is missing the required parameter. There should be -s and -M parameters together.");
    else
        load();
}

bool Ssl::CertificateDb::find(std::string const & host_name, Ssl::X509_Pointer & cert, Ssl::EVP_PKEY_Pointer & pkey)
{
    FileLocker db_locker(db_full);
    load();
    return pure_find(host_name, cert, pkey);
}

bool Ssl::CertificateDb::addCertAndPrivateKey(Ssl::X509_Pointer & cert, Ssl::EVP_PKEY_Pointer & pkey)
{
    FileLocker db_locker(db_full);
    load();
    if (!db || !cert || !pkey || min_db_size > max_db_size)
        return false;
    Row row;
    ASN1_INTEGER * ai = X509_get_serialNumber(cert.get());
    std::string serial_string;
    Ssl::BIGNUM_Pointer serial(ASN1_INTEGER_to_BN(ai, NULL));
    {
        TidyPointer<char, tidyFree> hex_bn(BN_bn2hex(serial.get()));
        serial_string = std::string(hex_bn.get());
    }
    row.setValue(cnlSerial, serial_string.c_str());
    char ** rrow = TXT_DB_get_by_index(db.get(), cnlSerial, row.getRow());
    if (rrow != NULL)
        return false;

    {
        TidyPointer<char, tidyFree> subject(X509_NAME_oneline(X509_get_subject_name(cert.get()), NULL, 0));
        if (pure_find(subject.get(), cert, pkey))
            return true;
    }
    // check db size.
    while (max_db_size < size()) {
        if (!deleteInvalidCertificate())
            break;
    }

    while (max_db_size < size()) {
        deleteOldestCertificate();
    }

    row.setValue(cnlType, "V");
    ASN1_UTCTIME * tm = X509_get_notAfter(cert.get());
    row.setValue(cnlExp_date, std::string(reinterpret_cast<char *>(tm->data), tm->length).c_str());
    row.setValue(cnlFile, "unknown");
    {
        TidyPointer<char, tidyFree> subject(X509_NAME_oneline(X509_get_subject_name(cert.get()), NULL, 0));
        row.setValue(cnlName, subject.get());
    }

    if (!TXT_DB_insert(db.get(), row.getRow()))
        return false;

    row.reset();
    std::string filename(cert_full + "/" + serial_string + ".pem");
    FileLocker cert_locker(filename);
    if (!writeCertAndPrivateKeyToFile(cert, pkey, filename.c_str()))
        return false;
    addSize(filename);

    save();
    return true;
}

BIGNUM * Ssl::CertificateDb::getCurrentSerialNumber()
{
    FileLocker serial_locker(serial_full);
    // load serial number from file.
    Ssl::BIO_Pointer file(BIO_new(BIO_s_file()));
    if (!file)
        return NULL;

    if (BIO_rw_filename(file.get(), const_cast<char *>(serial_full.c_str())) <= 0)
        return NULL;

    Ssl::ASN1_INT_Pointer serial_ai(ASN1_INTEGER_new());
    if (!serial_ai)
        return NULL;

    char buffer[1024];
    if (!a2i_ASN1_INTEGER(file.get(), serial_ai.get(), buffer, sizeof(buffer)))
        return NULL;

    Ssl::BIGNUM_Pointer serial(ASN1_INTEGER_to_BN(serial_ai.get(), NULL));

    if (!serial)
        return NULL;

    // increase serial number.
    Ssl::BIGNUM_Pointer increased_serial(BN_dup(serial.get()));
    if (!increased_serial)
        return NULL;

    BN_add_word(increased_serial.get(), 1);

    // save increased serial number.
    if (BIO_seek(file.get(), 0))
        return NULL;

    Ssl::ASN1_INT_Pointer increased_serial_ai(BN_to_ASN1_INTEGER(increased_serial.get(), NULL));
    if (!increased_serial_ai)
        return NULL;

    i2a_ASN1_INTEGER(file.get(), increased_serial_ai.get());
    BIO_puts(file.get(),"\n");

    return serial.release();
}

void Ssl::CertificateDb::create(std::string const & db_path, int serial)
{
    if (db_path == "")
        throw std::runtime_error("Path to db is empty");
    std::string serial_full(db_path + "/" + serial_file);
    std::string db_full(db_path + "/" + db_file);
    std::string cert_full(db_path + "/" + cert_dir);
    std::string size_full(db_path + "/" + size_file);

#ifdef _SQUID_MSWIN_
    if (mkdir(db_path.c_str()))
#else
    if (mkdir(db_path.c_str(), 0777))
#endif
        throw std::runtime_error("Cannot create " + db_path);

#ifdef _SQUID_MSWIN_
    if (mkdir(cert_full.c_str()))
#else
    if (mkdir(cert_full.c_str(), 0777))
#endif
        throw std::runtime_error("Cannot create " + cert_full);

    Ssl::ASN1_INT_Pointer i(ASN1_INTEGER_new());
    ASN1_INTEGER_set(i.get(), serial);

    Ssl::BIO_Pointer file(BIO_new(BIO_s_file()));
    if (!file)
        throw std::runtime_error("SSL error");

    if (BIO_write_filename(file.get(), const_cast<char *>(serial_full.c_str())) <= 0)
        throw std::runtime_error("Cannot open " + cert_full + " to open");

    i2a_ASN1_INTEGER(file.get(), i.get());

    std::ofstream size(size_full.c_str());
    if (size)
        size << 0;
    else
        throw std::runtime_error("Cannot open " + size_full + " to open");
    std::ofstream db(db_full.c_str());
    if (!db)
        throw std::runtime_error("Cannot open " + db_full + " to open");
}

void Ssl::CertificateDb::check(std::string const & db_path, size_t max_db_size)
{
    CertificateDb db(db_path, max_db_size, 0);
}

std::string Ssl::CertificateDb::getSNString() const
{
    FileLocker serial_locker(serial_full);
    std::ifstream file(serial_full.c_str());
    if (!file)
        return "";
    std::string serial;
    file >> serial;
    return serial;
}

bool Ssl::CertificateDb::pure_find(std::string const & host_name, Ssl::X509_Pointer & cert, Ssl::EVP_PKEY_Pointer & pkey)
{
    if (!db)
        return false;

    Row row;
    row.setValue(cnlName, host_name.c_str());

    char **rrow = TXT_DB_get_by_index(db.get(), cnlName, row.getRow());
    if (rrow == NULL)
        return false;

    if (!sslDateIsInTheFuture(rrow[cnlExp_date])) {
        deleteByHostname(rrow[cnlName]);
        return false;
    }

    // read cert and pkey from file.
    std::string filename(cert_full + "/" + rrow[cnlSerial] + ".pem");
    FileLocker cert_locker(filename);
    readCertAndPrivateKeyFromFiles(cert, pkey, filename.c_str(), NULL);
    if (!cert || !pkey)
        return false;
    return true;
}

size_t Ssl::CertificateDb::size() const
{
    FileLocker size_locker(size_full);
    return readSize();
}

void Ssl::CertificateDb::addSize(std::string const & filename)
{
    FileLocker size_locker(size_full);
    writeSize(readSize() + getFileSize(filename));
}

void Ssl::CertificateDb::subSize(std::string const & filename)
{
    FileLocker size_locker(size_full);
    writeSize(readSize() - getFileSize(filename));
}

size_t Ssl::CertificateDb::readSize() const
{
    size_t db_size;
    std::ifstream size_file(size_full.c_str());
    if (!size_file && enabled_disk_store)
        throw std::runtime_error("cannot read \"" + size_full + "\" file");
    size_file >> db_size;
    return db_size;
}

void Ssl::CertificateDb::writeSize(size_t db_size)
{
    std::ofstream size_file(size_full.c_str());
    if (!size_file && enabled_disk_store)
        throw std::runtime_error("cannot write \"" + size_full + "\" file");
    size_file << db_size;
}

size_t Ssl::CertificateDb::getFileSize(std::string const & filename)
{
    std::ifstream file(filename.c_str(), std::ios::binary);
    file.seekg(0, std::ios_base::end);
    size_t file_size = file.tellg();
    return ((file_size + fs_block_size - 1) / fs_block_size) * fs_block_size;
}

void Ssl::CertificateDb::load()
{
    // Load db from file.
    Ssl::BIO_Pointer in(BIO_new(BIO_s_file()));
    if (!in || BIO_read_filename(in.get(), db_full.c_str()) <= 0)
        throw std::runtime_error("Uninitialized SSL certificate database directory: " + db_path + ". To initialize, run \"ssl_crtd -c -s " + db_path + "\".");

    bool corrupt = false;
    Ssl::TXT_DB_Pointer temp_db(TXT_DB_read(in.get(), cnlNumber));
    if (!temp_db)
        corrupt = true;

    // Create indexes in db.
    if (!corrupt && !TXT_DB_create_index(temp_db.get(), cnlSerial, NULL, LHASH_HASH_FN(index_serial_hash), LHASH_COMP_FN(index_serial_cmp)))
        corrupt = true;

    if (!corrupt && !TXT_DB_create_index(temp_db.get(), cnlName, NULL, LHASH_HASH_FN(index_name_hash), LHASH_COMP_FN(index_name_cmp)))
        corrupt = true;

    if (corrupt)
        throw std::runtime_error("The SSL certificate database " + db_path + " is curruted. Please rebuild");

    db.reset(temp_db.release());
}

void Ssl::CertificateDb::save()
{
    if (!db)
        throw std::runtime_error("The certificates database is not loaded");;

    // To save the db to file,  create a new BIO with BIO file methods.
    Ssl::BIO_Pointer out(BIO_new(BIO_s_file()));
    if (!out || !BIO_write_filename(out.get(), const_cast<char *>(db_full.c_str())))
        throw std::runtime_error("Failed to initialize " + db_full + " file for writing");;

    if (TXT_DB_write(out.get(), db.get()) < 0)
        throw std::runtime_error("Failed to write " + db_full + " file");
}

bool Ssl::CertificateDb::deleteInvalidCertificate()
{
    if (!db)
        return false;

    bool removed_one = false;
    for (int i = 0; i < sk_num(db.get()->data); i++) {
        const char ** current_row = ((const char **)sk_value(db.get()->data, i));

        if (!sslDateIsInTheFuture(current_row[cnlExp_date])) {
            std::string filename(cert_full + "/" + current_row[cnlSerial] + ".pem");
            FileLocker cert_locker(filename);
            sk_delete(db.get()->data, i);
            subSize(filename);
            remove(filename.c_str());
            removed_one = true;
            break;
        }
    }

    if (!removed_one)
        return false;
    return true;
}

bool Ssl::CertificateDb::deleteOldestCertificate()
{
    if (!db)
        return false;

    if (sk_num(db.get()->data) == 0)
        return false;

    std::string filename(cert_full + "/" + ((const char **)sk_value(db.get()->data, 0))[cnlSerial] + ".pem");
    FileLocker cert_locker(filename);
    sk_delete(db.get()->data, 0);
    subSize(filename);
    remove(filename.c_str());

    return true;
}

bool Ssl::CertificateDb::deleteByHostname(std::string const & host)
{
    if (!db)
        return false;

    for (int i = 0; i < sk_num(db.get()->data); i++) {
        const char ** current_row = ((const char **)sk_value(db.get()->data, i));
        if (host == current_row[cnlName]) {
            std::string filename(cert_full + "/" + current_row[cnlSerial] + ".pem");
            FileLocker cert_locker(filename);
            sk_delete(db.get()->data, i);
            subSize(filename);
            remove(filename.c_str());
            return true;
        }
    }
    return false;
}

bool Ssl::CertificateDb::IsEnabledDiskStore() const
{
    return enabled_disk_store;
}
