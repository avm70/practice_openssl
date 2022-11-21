#pragma once

#include <QString>
#include <QTextStream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/ocsp.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <sstream>
#include <MediaNet/Security/ICertificateStorage.h>
#include <MediaNet/Security/IKeyStorage.h>
#include <QSslCertificate>
#include <QFile>
#include <QDir>

class CertificateImporter : public QObject
{
    Q_OBJECT
public:
    CertificateImporter( const QSharedPointer<MediaNet::Security::ICertificateStorage> &certificateStorage,
                        const QSharedPointer<MediaNet::Security::IKeyStorage> &keyStorage );
    void import( const QStringList &filenames, const bool &toServer );
signals:
    void end( int n );
private:
    QSharedPointer<MediaNet::Security::ICertificateStorage> mCertificateStorage;
    QSharedPointer<MediaNet::Security::IKeyStorage> mKeyStorage;
    void importCertToServer( X509 *x509, EVP_PKEY *key );
    void importCert( X509 *x509, EVP_PKEY *key );
    void importKeyToServer( QByteArray serialNumber, EVP_PKEY *key );
    void importKey( QByteArray serialNumber, EVP_PKEY *key );
    X509 *parse_cert( FILE *file, EVP_PKEY **key, const bool &toServer );
    EVP_PKEY *parse_key( FILE* file, QString fileName );
    QString getSerialNumber( X509 *x509 );
};
