#include "CertificateWidget.h"

#include "CertificateDialog.h"
#include "RequestDialog.h"
#include "SelectCertificateDialog.h"
#include "SelectCaCertificateDialog.h"
#include "CertificateImporter.h"

#include <MediaNet/Auth/LocalSystem.h>
#include <MediaNet/Utils/Logger.h>
#include <MediaNet/Utils/ConnectableWaiter.h>

#include <QBoxLayout>
#include <QHeaderView>
#include <QMessageBox>

#include <QLoggingCategory>

Q_LOGGING_CATEGORY(TAG_CERTIFICATE_WIDGET, "medianet.modules.GuiSecurity.CertificateWidget")

CertificateWidget::CertificateWidget(const QSharedPointer<MediaNet::System> & system,
                                     const QSharedPointer<MediaNet::Security::IKeyStorage> & keyStorage,
                                     const QSharedPointer<MediaNet::Security::IRequestStorage> & requestStorage,
                                     const QSharedPointer<MediaNet::Security::ICertificateStorage> & certificateStorage,
                                     const QSharedPointer<MediaNet::Security::IGenerator> & generator,
                                     const QSharedPointer<MediaNet::Vpn::IVpnManager> & vpnManager)
    :
      mSystem(system),
      mKeyStorage(keyStorage),
      mRequestStorage(requestStorage),
      mCertificateStorage(certificateStorage),
      mGenerator(generator),
      mVpnManager(vpnManager),
      mCertificateModel(mKeyStorage, mRequestStorage, mCertificateStorage),
      mImportCert(QIcon(":/GuiSecurity/icons/sync.png"), "Импорт сертификатов"),
      mAddSelfSignedCertButton(QIcon(":/GuiSecurity/icons/self_cert.png"), "Создать самозаверенный сертификат"),
      mAddRequestButton(QIcon(":/GuiSecurity/icons/req.png"), "Создать запрос на подпись"),
      mSyncButton(QIcon(":/GuiSecurity/icons/sync.png"), "Добавить сертификат из другой системы"),
      mRemoveButton(QIcon(":/icons/no.png"), "")
{
    QBoxLayout *tableLayout = new QVBoxLayout(this);

    mTableView.setModel(&mCertificateModel);
    mTableView.setSelectionBehavior(QAbstractItemView::SelectRows);
    mTableView.setSelectionMode(QAbstractItemView::SingleSelection);
    mTableView.setEditTriggers(QAbstractItemView::NoEditTriggers);
    mTableView.verticalHeader()->hide();

    mTableView.horizontalHeader()->setSectionResizeMode(CertificateModel::CertificateIconRole, QHeaderView::ResizeToContents);
    mTableView.horizontalHeader()->setSectionResizeMode(CertificateModel::PrivateKeyIconRole, QHeaderView::ResizeToContents);
    mTableView.horizontalHeader()->setSectionResizeMode(CertificateModel::CertificateLabelColumnRole, QHeaderView::Stretch);
    mTableView.horizontalHeader()->setSectionResizeMode(CertificateModel::CertificateOrganizationColumnRole, QHeaderView::Stretch);
    mTableView.horizontalHeader()->setSectionResizeMode(CertificateModel::CertificateSerialNumber, QHeaderView::ResizeToContents);
    mTableView.horizontalHeader()->setSectionResizeMode(CertificateModel::CertificateEffectiveDateColumnRole, QHeaderView::ResizeToContents);
    mTableView.horizontalHeader()->setSectionResizeMode(CertificateModel::CertificateExpiryDateColumnRole, QHeaderView::ResizeToContents);

    tableLayout->addWidget(&mTableView);

    mAddSelfSignedCertButton.setMinimumHeight(35);
    mAddRequestButton.setMinimumHeight(35);
    mSyncButton.setMinimumHeight(35);
    mRemoveButton.setMinimumHeight(35);
    mImportCert.setMinimumHeight(35);

    mAddSelfSignedCertButton.setEnabled(false);
    mAddRequestButton.setEnabled(false);
    mSyncButton.setEnabled(false);
    mRemoveButton.setEnabled(false);
    mImportCert.setEnabled(false);

    QBoxLayout *controlsLayout = new QHBoxLayout();
    controlsLayout->setContentsMargins(0, 0, 0, 0);
    controlsLayout->addWidget(&mAddSelfSignedCertButton, 1);
    controlsLayout->addWidget(&mAddRequestButton, 1);
    controlsLayout->addWidget(&mImportCert, 1);
    controlsLayout->addWidget(&mSyncButton, 1);
    controlsLayout->addWidget(&mRemoveButton, 0, Qt::AlignRight);

    tableLayout->addLayout(controlsLayout, 0);
    setLayout(tableLayout);
    layout()->setContentsMargins(0, 0, 0, 0);

    QList<QSharedPointer<MediaNet::Connectable> > connectables{ mKeyStorage, mRequestStorage, mCertificateStorage };
    if( mGenerator )
    {
        connectables << mGenerator;
    }

    //лямбды удаляются вместе с ConnectableWaiter
    new MediaNet::Utils::ConnectableWaiter( this, connectables,
                                            [ this ]()
    {
        mSyncButton.setEnabled(true);

        if (this->mSystem->getTopology().size() < 2)
        {
            mImportCert.setEnabled(true);
            connect(&mImportCert, &QPushButton::clicked, this, &CertificateWidget::onImportCertButtonClicked);
        }
        else
        {
            mImportCert.hide();
        }

        mRemoveButton.setEnabled(mTableView.selectionModel()->currentIndex().isValid());
        connect(&mSyncButton, &QPushButton::clicked, this, &CertificateWidget::onSyncCaButtonClicked);
        connect(&mRemoveButton, &QPushButton::clicked, this, &CertificateWidget::onRemoveButtonClicked);

        connect(mTableView.selectionModel(), &QItemSelectionModel::currentRowChanged, this, &CertificateWidget::onRowChanged);
        connect(&mTableView, &QTableView::doubleClicked, this, &CertificateWidget::onDoubleClicked);

        if( mGenerator ){
            mAddSelfSignedCertButton.setEnabled(true);
            mAddRequestButton.setEnabled(true);
            connect(&mAddSelfSignedCertButton, &QPushButton::clicked, this, &CertificateWidget::onAddCertificateButtonClicked);
            connect(&mAddRequestButton, &QPushButton::clicked, this, &CertificateWidget::onAddRequestButtonClicked);
        }
    } );
}

CertificateWidget::~CertificateWidget()
{
    qCDebug(TAG_CERTIFICATE_WIDGET) << "Удален виджет" << this;
}

void CertificateWidget::onRowChanged(QModelIndex current, QModelIndex)
{
    mRemoveButton.setEnabled(current.isValid());
}

void CertificateWidget::onSyncCaButtonClicked()
{
    SelectCaCertificateDialog dialog;
    if (dialog.exec() == QDialog::Accepted)
    {
        QSslCertificate certificate = dialog.selectedCertificate();

        if (!certificate.isNull())
        {
            mnLog(mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность")
                    << "Добавление сертификата" << certificate.serialNumber() << "из другой системы";

            auto reply = mCertificateStorage->addCertificate(certificate);
            if (reply->isFinished())
            {
                onAddCertificateFinished(reply);
            }
            else
            {
                connect(reply, SIGNAL(finished(MediaNet::Utils::BoolReply*)),
                        this, SLOT(onAddCertificateFinished(MediaNet::Utils::BoolReply*)));
                showWaitDialog();
            }
        }
    }
}

void CertificateWidget::onAddCertificateButtonClicked()
{
    if (mGenerator.isNull()) return;

    GenerateCertificateDialog dialog( mSystem );
    if (dialog.exec() == QDialog::Accepted)
    {
        mnLog(mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность")
                << "Генерация нового " << (dialog.isCa() ? "корневого (CA)" : "самозаверенного") << " сертификата...";

        MediaNet::Utils::BoolReply* reply = dialog.generate(mGenerator);
        if (reply->isFinished())
        {
            onGenerateFinished(reply);
        }
        else
        {
            connect(reply, SIGNAL(finished(MediaNet::Utils::BoolReply*)),
                    this, SLOT(onGenerateFinished(MediaNet::Utils::BoolReply*)));
            showWaitDialog();
        }
    }
}

void CertificateWidget::onAddRequestButtonClicked()
{
    if (mGenerator.isNull()) return;

    GenerateRequestDialog dialog;
    if (dialog.exec() == QDialog::Accepted)
    {
        mnLog(mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность")
                << "Генерация нового запроса...";

        MediaNet::Utils::BoolReply* reply = dialog.generate(mGenerator);
        if (reply->isFinished())
        {
            onGenerateFinished(reply);
        }
        else
        {
            connect(reply, SIGNAL(finished(MediaNet::Utils::BoolReply*)),
                    this, SLOT(onGenerateFinished(MediaNet::Utils::BoolReply*)));
            showWaitDialog();
        }
    }
}

void CertificateWidget::onRemoveButtonClicked()
{
    bool isCert = false;
    QByteArray serialNumber = mCertificateModel.getSerialNumberByIndex(mTableView.currentIndex(), isCert);
    if( isCert )
    {
        auto onReplyFinished = [this, serialNumber]( MediaNet::Vpn::StatusReply * reply )
        {
            disconnect(reply, nullptr, nullptr, nullptr);
            bool delFlag = true;
            MediaNet::Vpn::Status status;
            try
            {
                status = reply->getResult();
                if( status == MediaNet::Vpn::Status::ClientRunning || status == MediaNet::Vpn::Status::ClientStarting
                    || status == MediaNet::Vpn::Status::ServerRunning || status == MediaNet::Vpn::Status::ServerStarting )
                {
                    delFlag = false;
                }
            }
            catch( const MediaNet::Exception & ex ) {}

            if( delFlag )
            {
                if( QMessageBox::warning( this, "Удаление сертификата", "Удалить указанный сертификат?", "Да", "Нет" ) != 0 )
                    return;
                mnWarningLog( mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность" )
                            << "Удаление сертификата:" << serialNumber;
                mCertificateStorage->removeCertificate( serialNumber )->getResult( false );
                mRequestStorage->removeRequest( serialNumber )->getResult( false );
                mKeyStorage->removeKey( serialNumber )->getResult( false );
            }
            else
            {
                if( status == MediaNet::Vpn::Status::ClientRunning || status == MediaNet::Vpn::Status::ClientStarting )
                {
                    auto onGetClientConfig = [this, serialNumber]( MediaNet::Vpn::ClientConfigReply * reply )
                    {
                        try
                        {
                            MediaNet::Vpn::ClientConfig config = reply->getResult();
                            if( config.certSerialNumber == serialNumber || config.caCertSerialNumber == serialNumber )
                            {
                                QMessageBox::warning( this, "Удаление сертификата", "VPN работает с сертификатом", "OK" );
                                return;
                            }
                            else
                            {
                                if( QMessageBox::warning( this, "Удаление сертификата", "Удалить указанный сертификат?", "Да", "Нет" ) != 0 ) return;

                                mnWarningLog( mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность" )
                                            << "Удаление сертификата:" << serialNumber;
                                mCertificateStorage->removeCertificate( serialNumber )->getResult( false );
                                mRequestStorage->removeRequest( serialNumber )->getResult( false );
                                mKeyStorage->removeKey( serialNumber )->getResult( false );
                            }
                        }
                        catch( const MediaNet::Exception & ex ) {}
                    };
                    MediaNet::Vpn::ClientConfigReply *reply = mVpnManager->getClientConfig();
                    connect(reply, static_cast<void(MediaNet::Vpn::ClientConfigReply::*)(MediaNet::Vpn::ClientConfigReply*)>(&MediaNet::Vpn::ClientConfigReply::finished),
                            this, onGetClientConfig);
                    if( reply->isFinished() )
                    {
                        onGetClientConfig( reply );
                    }
                }
                else if( status == MediaNet::Vpn::Status::ServerRunning || status == MediaNet::Vpn::Status::ServerStarting )
                {
                    auto onGetServerConfig = [this, serialNumber]( MediaNet::Vpn::ServerConfigReply * reply )
                    {
                        try
                        {
                            MediaNet::Vpn::ServerConfig config = reply->getResult();
                            if( config.certSerialNumber == serialNumber || config.caCertSerialNumber == serialNumber )
                            {
                                QMessageBox::warning( this, "Удаление сертификата", "VPN работает с сертификатом", "OK" );
                                return;
                            }
                            else
                            {
                                if( QMessageBox::warning( this, "Удаление сертификата", "Удалить указанный сертификат?", "Да", "Нет" ) != 0 )
                                    return;
                                mnWarningLog( mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность" )
                                            << "Удаление сертификата:" << serialNumber;
                                mCertificateStorage->removeCertificate( serialNumber )->getResult( false );
                                mRequestStorage->removeRequest( serialNumber )->getResult( false );
                                mKeyStorage->removeKey( serialNumber )->getResult( false );
                            }
                        }
                        catch( const MediaNet::Exception & ex ) {}
                    };
                    MediaNet::Vpn::ServerConfigReply *reply = mVpnManager->getServerConfig();
                    connect(reply, static_cast<void(MediaNet::Vpn::ServerConfigReply::*)(MediaNet::Vpn::ServerConfigReply*)>(&MediaNet::Vpn::ServerConfigReply::finished),
                            this, onGetServerConfig);
                    if( reply->isFinished() )
                    {
                        onGetServerConfig( reply );
                    }
                }
            }
        };
        MediaNet::Vpn::StatusReply *reply = mVpnManager->getStatus();

        connect(reply, static_cast<void(MediaNet::Vpn::StatusReply::*)(MediaNet::Vpn::StatusReply*)>(&MediaNet::Vpn::StatusReply::finished),
                this, onReplyFinished);

        if( reply->isFinished() )
        {
            onReplyFinished( reply );
        }
    }
    else
    {
        if( QMessageBox::warning( this, "Удаление запроса", "Удалить указанный запрос?", "Да", "Нет" ) != 0 )
            return;
        mnWarningLog( mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность" )
                    << "Удаление запроса:" << serialNumber;
        mCertificateStorage->removeCertificate( serialNumber )->getResult( false );
        mRequestStorage->removeRequest( serialNumber )->getResult( false );
        mKeyStorage->removeKey( serialNumber )->getResult( false );
    }
}

void CertificateWidget::onDoubleClicked(QModelIndex index)
{
    bool isCert = false;
    QByteArray serialNumber = mCertificateModel.getSerialNumberByIndex(index, isCert);

    if (isCert)
    {
        auto reply = mCertificateStorage->getCertificate(serialNumber);
        if (reply->isFinished())
        {
            showCertificateDialog(reply);
        }
        else
            connect(reply, SIGNAL(finished(MediaNet::Security::CertificateReply*)),
                    this, SLOT(showCertificateDialog(MediaNet::Security::CertificateReply*)));
    }
    else
    {
        auto reply = mRequestStorage->getRequest(serialNumber);
        if (reply->isFinished())
        {
            showRequestDialog(reply);
        }
        else
            connect(reply, SIGNAL(finished(MediaNet::Security::RequestReply*)),
                    this, SLOT(showRequestDialog(MediaNet::Security::RequestReply*)));
    }
}

void CertificateWidget::onGenerateFinished(MediaNet::Utils::BoolReply * reply)
{
    hideWaitDialog();

    try
    {
        if (!reply->getResult())
            throw MediaNet::Exception("Failed");

        mnLog(mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность")
                << "Генерация сертификата/запроса завершена успешно";
    }
    catch(const MediaNet::Exception & ex)
    {
        qCCritical(TAG_CERTIFICATE_WIDGET) << QString::fromLocal8Bit(ex.what());
        QMessageBox::critical(this, "Генерация сертификата/запроса", "Не удалось сгенерировать сертификат/запрос.");
    }
}

void CertificateWidget::showCertificateDialog(MediaNet::Security::CertificateReply * reply)
{
    try
    {
        CertificateDialog dialog(reply->getResult(), mSystem);
        dialog.exec();
    }
    catch(const MediaNet::Exception & ex)
    {
        qCCritical(TAG_CERTIFICATE_WIDGET) << QString::fromLocal8Bit(ex.what());
    }
}

void CertificateWidget::showRequestDialog(MediaNet::Security::RequestReply * reply)
{
    try
    {
        RequestDialog dialog(reply->getResult());
        connect(&dialog, &RequestDialog::subscribe, this, &CertificateWidget::subscribe);
        dialog.exec();
    }
    catch(const MediaNet::Exception & ex)
    {
        qCCritical(TAG_CERTIFICATE_WIDGET) << QString::fromLocal8Bit(ex.what());
    }
}

void CertificateWidget::subscribe(MediaNet::Security::Request request)
{
    SelectCaCertificateDialog dialog;
    if (dialog.exec() == QDialog::Accepted)
    {
        QByteArray caSerialNumber = dialog.selectedCaSerialNumber();
        auto subscriber = dialog.selectedSubscriber();

        try
        {
            mnLog(mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность")
                    << "Подпись запроса " << request.serialNumber << " на системе"
                    << dialog.selectedSystemName() << "используя CA сертификат" << caSerialNumber << "...";

            if (subscriber.isNull() || caSerialNumber.isEmpty())
                throw MediaNet::Exception("Удален Subscriber или CA-сертификат");

            auto reply = subscriber->subscribe(request, caSerialNumber);
            if (reply->isFinished())
            {
                onSubscribeFinished(reply);
            }
            else
            {
                connect(reply, SIGNAL(finished(MediaNet::Security::CertificateReply*)),
                        this, SLOT(onSubscribeFinished(MediaNet::Security::CertificateReply*)));
                showWaitDialog();
            }
        }
        catch(const MediaNet::Exception & ex)
        {
            qCCritical(TAG_CERTIFICATE_WIDGET) << QString::fromLocal8Bit(ex.what());
            QMessageBox::critical(this, "Подписать запрос", "Не удалось подписать запрос.");
        }
    }
}

void CertificateWidget::onSubscribeFinished(MediaNet::Security::CertificateReply * reply)
{
    try
    {
        QSslCertificate certificate = reply->getResult();

        mnLog(mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность")
                << "Подпись запроса " << certificate.serialNumber() << " выполнена успешна, добавление сертификата";

        auto boolReply = mCertificateStorage->addCertificate(certificate);
        if (boolReply->isFinished())
        {
            onAddCertificateFinished(boolReply, certificate.serialNumber());
        }
        else
        {
            // лямбда удаляется при удалении boolReply либо this
            connect(boolReply, static_cast<void (MediaNet::Utils::BoolReply::*)(MediaNet::Utils::BoolReply*)>
                    (&MediaNet::Utils::BoolReply::finished), this, [this, certificate](MediaNet::Utils::BoolReply *innerReply)
            {
                onAddCertificateFinished(innerReply, certificate.serialNumber());
            });
            showWaitDialog();
        }
    }
    catch(const MediaNet::Exception & ex)
    {
        qCCritical(TAG_CERTIFICATE_WIDGET) << QString::fromLocal8Bit(ex.what());
        hideWaitDialog();
        QMessageBox::critical(this, "Подписать запрос", "Не удалось подписать запрос.");
    }
}

void CertificateWidget::onAddCertificateFinished(MediaNet::Utils::BoolReply *reply, const QByteArray & serialNumber)
{
    try
    {
        if (reply->getResult())
        {
            mnLog(mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность")
                    << "Добавлен сертификат из запроса. Удаление этого запроса...";

            auto boolReply = mRequestStorage->removeRequest(serialNumber);
            if (boolReply->isFinished())
            {
                onRemoveRequestFinished(boolReply);
            }
            else
            {
                connect(boolReply, SIGNAL(finished(MediaNet::Utils::BoolReply*)),
                        this, SLOT(onRemoveRequestFinished(MediaNet::Utils::BoolReply*)));
                showWaitDialog();
            }
        }
    }
    catch(const MediaNet::Exception & ex)
    {
        qCCritical(TAG_CERTIFICATE_WIDGET) << QString::fromLocal8Bit(ex.what());
    }
}

void CertificateWidget::onRemoveRequestFinished(MediaNet::Utils::BoolReply *reply)
{
    hideWaitDialog();

    try
    {
        if (!reply->getResult())
            throw MediaNet::Exception("Failed");

        mnLog(mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность")
                << "Запроса удален";
    }
    catch(const MediaNet::Exception & ex)
    {
        qCCritical(TAG_CERTIFICATE_WIDGET) << QString::fromLocal8Bit(ex.what());
    }
}

void CertificateWidget::onAddCertificateFinished(MediaNet::Utils::BoolReply *reply)
{
    hideWaitDialog();

    try
    {
        if (!reply->getResult())
            throw MediaNet::Exception("Failed");

        mnLog(mSystem, MediaNet::Auth::LocalSystem::instance()->getUser().getName(), "Безопасность")
                << "Добавлен сертификат из другой системы";
    }
    catch(const MediaNet::Exception & ex)
    {
        qCCritical(TAG_CERTIFICATE_WIDGET) << QString::fromLocal8Bit(ex.what());
        QMessageBox::critical(this, "Добавить сертификат из другой системы", "Не удалось добавить сертификат.");
    }
}

void CertificateWidget::showWaitDialog()
{
    if (mWaitDialog == nullptr)
    {
        mWaitDialog = new QDialog(this, Qt::Window | Qt::CustomizeWindowHint | Qt::WindowTitleHint| Qt::WindowSystemMenuHint);
        QLabel *label = new QLabel("Пожалуйста, подождите...", mWaitDialog);
        label->setGeometry(10, 25, 320, 15);
        label->setAlignment(Qt::AlignCenter);
        mWaitDialog->setWindowTitle("Безопасность");
        mWaitDialog->resize(340, 70);
        mWaitDialog->exec();
    }
}

void CertificateWidget::hideWaitDialog()
{
    if (mWaitDialog != nullptr)
    {
        mWaitDialog->close();
        mWaitDialog->deleteLater();
        mWaitDialog = nullptr;
    }
}

void CertificateWidget::onImportCertButtonClicked()
{
    QFileDialog dialog(this);
    dialog.setFileMode(QFileDialog::ExistingFiles);
    connect(&dialog, &QFileDialog::filesSelected, this, &CertificateWidget::importCertificates);
    dialog.exec();
}

void CertificateWidget::importCertificates(const QStringList& arg)
{
    CertificateImporter * impl = new CertificateImporter( mCertificateStorage, mKeyStorage );
    connect( impl, &CertificateImporter::end, this, &CertificateWidget::onImportEnd );
    if( mSystem->getTopology().size() == 0 )
    {
        impl->import( arg, false );
    }
    else
    {
        impl->import( arg, true );
    }
}

void CertificateWidget::onImportEnd( int flag )
{
    if( flag == -1 )
    {
        QMessageBox::critical( this, "Импорт сертификатов", "Ошибка при открытии сертификата" );
    }
    else if( flag == 0 )
    {
        QMessageBox::information( this, "Импорт сертификатов", "Импорт завершен" );
    }
    else
    {
        QMessageBox::information( this, "Импорт сертификатов", "Импорт завершен, ключи без сертификата не импортированы" );
    }
    QObject * obj = sender();
    delete obj;
}
