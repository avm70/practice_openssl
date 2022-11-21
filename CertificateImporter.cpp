#include "CertificateImporter.h"
#include <QLoggingCategory>
#include <QInputDialog>

Q_LOGGING_CATEGORY(TAG_CERTIFICATE_IMPORTER, "medianet.modules.GuiSecurity.CertificateImporter")

int cb( char *buf, int size, int rwflag, void *u )
{
    QString keyName = (char *) u;
    bool accepted;
    QString password = QInputDialog::getText( 0,
                                             "Ввод пароля",
                                             "Введите пароль для ключа\n" + keyName,
                                             QLineEdit::Password,
                                             "",
                                             &accepted
                                             );
    if( accepted )
    {
        QByteArray tmpArray = password.toLocal8Bit();
        char* tmp = tmpArray.data();
        int len = strlen( tmp );
        memcpy( buf, tmp, len );
        return len;
    }

    return 0;
}


CertificateImporter::CertificateImporter( const QSharedPointer<MediaNet::Security::ICertificateStorage> &certificateStorage,
                                         const QSharedPointer<MediaNet::Security::IKeyStorage> &keyStorage ) :
    mCertificateStorage( certificateStorage ),
    mKeyStorage( keyStorage )
{
    OpenSSL_add_all_algorithms();
}

void CertificateImporter::importCertToServer( X509 *x509, EVP_PKEY *key )
{
    BIO *bio = BIO_new( BIO_s_mem() );
    PEM_write_bio_X509( bio, x509 );
    BUF_MEM *mem = nullptr;
    BIO_get_mem_ptr( bio, &mem );
    QByteArray tmp( mem->data, mem->length );
    QSslCertificate sslcert( tmp );
    mCertificateStorage->addCertificate( sslcert );
    BIO_free( bio );
    if( key != nullptr )
    {
        BIO *biokey = BIO_new( BIO_s_mem() );
        PEM_write_bio_PrivateKey( biokey, key, nullptr, nullptr, 0, 0, nullptr );
        BUF_MEM *memkey = nullptr;
        BIO_get_mem_ptr( biokey, &memkey );
        QByteArray tmpkey( memkey->data, memkey->length );
        MediaNet::Security::PrivateKey pkey;
        pkey.data = tmpkey;
        pkey.serialNumber = sslcert.serialNumber();
        mKeyStorage->addKey( pkey );
        BIO_free( biokey );
    }
}

void CertificateImporter::importCert( X509 *x509, EVP_PKEY *key )
{
    QString path = "security/storage/";
    QString crtname = path + getSerialNumber( x509 ) + ".crt.pem";
    QByteArray serialNumber( getSerialNumber( x509 ).toLocal8Bit() );
    serialNumber.replace( '-', ':' );
    QFileInfo file( crtname );
    if( file.exists() )
    {
        return;
    }
    FILE *out = fopen( QByteArray( crtname.toLocal8Bit() ).data(), "w+" );
    if( out != nullptr )
    {
        if( !PEM_write_X509( out, x509 ) )
        {
            fclose( out );
            return;
        }
        fclose( out );
        QSslCertificate tmp;
        QList<QSslCertificate> list = tmp.fromPath( crtname );
        mCertificateStorage->addCertificate( list.at(0) );
        if( key != nullptr )
        {
            QString keyname = path + getSerialNumber( x509 ) + ".key.pem";
            FILE *outkey = fopen( QByteArray( keyname.toLocal8Bit() ).data(), "w+" );
            if (outkey != nullptr)
            {
                if( !PEM_write_PrivateKey( outkey, key, nullptr, nullptr, 0, 0, nullptr ) )
                {
                    fclose( outkey );
                    return;
                }
                MediaNet::Security::PrivateKey pkey;
                pkey.serialNumber = serialNumber;
                rewind( outkey );
                QFile file;
                if( file.open( outkey, QIODevice::ReadOnly ) )
                {
                    pkey.data = file.readAll();
                    file.close();
                    fclose( outkey );
                }
                mKeyStorage->addKey( pkey );
            }
            else
            {
                return;
            }
        }
    }
    else
    {
        qCDebug( TAG_CERTIFICATE_IMPORTER ) << "file error";
        return;
    }
}

void CertificateImporter::importKeyToServer( QByteArray serialNumber, EVP_PKEY *key )
{
    BIO *biokey = BIO_new( BIO_s_mem() );
    PEM_write_bio_PrivateKey( biokey, key, nullptr, nullptr, 0, 0, nullptr );
    BUF_MEM *memkey = nullptr;
    BIO_get_mem_ptr( biokey, &memkey );
    QByteArray tmpkey( memkey->data, memkey->length );
    MediaNet::Security::PrivateKey pkey;
    pkey.data = tmpkey;
    pkey.serialNumber = serialNumber;
    mKeyStorage->addKey( pkey );
    BIO_free( biokey );
}

void CertificateImporter::importKey( QByteArray serialNumber, EVP_PKEY *key )
{
    QString path = "security/storage/";
    serialNumber.replace( ':', '-' );
    QString serial( serialNumber );
    QString keyname = path + serial + ".key.pem";
    QFileInfo file( keyname );
    if( file.exists() )
    {
        return;
    }
    FILE *outkey = fopen( QByteArray( keyname.toLocal8Bit() ).data(), "w+" );
    if( outkey != nullptr )
    {
        if( !PEM_write_PrivateKey( outkey, key, nullptr, nullptr, 0, 0, nullptr ) )
        {
            fclose( outkey );
            return;
        }
        MediaNet::Security::PrivateKey pkey;
        serialNumber.replace( '-', ':' );
        pkey.serialNumber = serialNumber;
        rewind( outkey );
        QFile file;
        if( file.open( outkey, QIODevice::ReadOnly ) )
        {
            pkey.data = file.readAll();
            file.close();
            fclose( outkey );
        }
        mKeyStorage->addKey( pkey );
    }
    else
    {
        return;
    }
}

void CertificateImporter::import( const QStringList &filenames, const bool &toServer )
{
    QList<EVP_PKEY*> keys;
    QList<X509*> certs;
    foreach( const QString name, filenames )
    {
        FILE *file = fopen( QByteArray( name.toLocal8Bit() ).data(), "rb" );
        EVP_PKEY *key = parse_key( file, name );
        if( key == nullptr )
        {
            rewind( file );
            X509* crt = parse_cert( file, &key, toServer );
            if( crt != nullptr && key != nullptr )
            {
                if( toServer )
                {
                    importCertToServer( crt, key );
                }
                else
                {
                    importCert( crt, key );
                }
            }
            else if( crt != nullptr )
            {
                certs.push_back( crt );
            }
            else
            {
                emit end( -1 );
            }
        }
        else
        {
            keys.push_back( key );
        }
    }
    foreach( X509 *cert, certs )
    {
        foreach( EVP_PKEY *key, keys )
        {
            if( X509_check_private_key( cert, key ) == 1 )
            {
                keys.removeOne( key );
                certs.removeOne( cert );
                if( toServer )
                {
                    importCertToServer( cert, key );
                }
                else
                {
                    importCert( cert, key );
                }
            }
        }
        if( certs.contains( cert ) )
        {
            if( toServer )
            {
                importCertToServer( cert, nullptr );
            }
            else
            {
                importCert( cert, nullptr );
            }
        }
    }
    if( keys.size() != 0 )
    {
        auto onReplyFinished = [this, toServer, keys]( MediaNet::Security::ListCertificateReply * reply ){
            QList<QSslCertificate> sslcerts;
            try
            {
                for( const QSslCertificate & certificate : reply->getResult() )
                {
                    sslcerts.push_back( certificate );
                }
            }
            catch( const MediaNet::Exception & ex )
            {
                qCCritical( TAG_CERTIFICATE_IMPORTER ) << QString::fromLocal8Bit( ex.what() );
            }
            int i = 0;
            for( QSslCertificate & sslcert : sslcerts )
            {
                QByteArray data = sslcert.toPem();
                BIO *bio = BIO_new( BIO_s_mem() );
                BIO_puts( bio, data.data() );
                X509 *crt = PEM_read_bio_X509( bio, nullptr, nullptr, nullptr );
                foreach( EVP_PKEY *key, keys )
                {
                    if( X509_check_private_key( crt, key ) == 1 )
                    {
                        if( toServer )
                        {
                            importKeyToServer( sslcert.serialNumber(), key );
                        }
                        else
                        {
                            importKey( sslcert.serialNumber(), key );
                        }
                        i++;
                    }
                }
            }
            emit end( keys.size() - i );
        };
        auto reply = mCertificateStorage->getCertificates();
        connect( reply, static_cast<void(MediaNet::Security::ListCertificateReply::*)(MediaNet::Security::ListCertificateReply*)>
                 (&MediaNet::Security::ListCertificateReply::finished), this, onReplyFinished );
        if( reply->isFinished() ) onReplyFinished( reply );
    }
    else
    {
        emit end( keys.size() );
    }
}

X509 *CertificateImporter::parse_cert( FILE *file, EVP_PKEY **key, const bool &toServer )
{
    X509 *x509 = PEM_read_X509( file, nullptr, nullptr, nullptr );
    if( x509 == nullptr )
    {
        rewind( file );
        x509 = d2i_X509_fp( file, nullptr );
        if( x509 == nullptr )
        {
            rewind( file );
            PKCS7 *p7_cert = PEM_read_PKCS7( file, nullptr, nullptr, nullptr );
            if( p7_cert != nullptr )
            {
                x509 = sk_X509_value( p7_cert->d.sign->cert, 0 );
            }
            else
            {
                rewind( file );
                PKCS12 *p12_crt = nullptr;
                STACK_OF( X509 ) *add = nullptr;
                d2i_PKCS12_fp( file, &p12_crt );
                PKCS12_parse( p12_crt, nullptr, key, &x509, &add );
                if( add != nullptr )
                {
                    for( int i = 0; i < sk_X509_num(add); i++ )
                    {
                        if( toServer )
                        {
                            importCertToServer( sk_X509_value( add, i ), nullptr );
                        }
                        else
                        {
                            importCert( sk_X509_value( add, i ), nullptr );
                        }
                    }
                }
            }
        }
    }
    return x509;
}

EVP_PKEY *CertificateImporter::parse_key( FILE *file, QString fileName )
{
    QByteArray data = fileName.toLocal8Bit();
    char* arg = data.data();
    EVP_PKEY *key = PEM_read_PrivateKey( file, nullptr, cb, arg );
    if( key == nullptr )
    {
        rewind( file );
        key = d2i_PrivateKey_fp( file, nullptr );
    }
    return key;
}

QString CertificateImporter::getSerialNumber( X509 *x509 )
{
    static const char hexbytes[] = "0123456789abcdef";
    ASN1_INTEGER *bs = X509_get_serialNumber( x509 );
    QString sn;
    QTextStream ashex( &sn );
    for( int i = 0; i < bs->length; i++ )
    {
        ashex << hexbytes[ ( bs->data[i]&0xf0 ) >> 4  ] ;
        ashex << hexbytes[ ( bs->data[i]&0x0f ) >> 0  ] ;
        if( i != bs->length - 1 )
            ashex << "-";
    }
    return sn;
}
