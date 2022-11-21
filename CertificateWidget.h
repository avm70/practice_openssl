#pragma once

#include <functional>

#include <QWidget>
#include <QTableView>
#include <QPushButton>
#include <QMenu>

#include <MediaNet/System.h>
#include <MediaNet/Utils/ThrowIfNull.h>

#include <MediaNet/Security/IKeyStorage.h>
#include <MediaNet/Security/ICertificateStorage.h>
#include <MediaNet/Security/IRequestStorage.h>
#include <MediaNet/Security/IGenerator.h>
#include <MediaNet/Security/ISubscriber.h>
#include <MediaNet/Vpn/IVpnManager.h>

#include "CertificateModel.h"

class CertificateWidget : public QWidget
{
    Q_OBJECT
public:
    explicit CertificateWidget(const QSharedPointer<MediaNet::System> & system,
                               const QSharedPointer<MediaNet::Security::IKeyStorage> &keyStorage,
                               const QSharedPointer<MediaNet::Security::IRequestStorage> &requestStorage,
                               const QSharedPointer<MediaNet::Security::ICertificateStorage> &certificateStorage,
                               const QSharedPointer<MediaNet::Security::IGenerator> &generator,
                               const QSharedPointer<MediaNet::Vpn::IVpnManager> &vpnManager) /*throw (MediaNet::Exception)*/;
    virtual ~CertificateWidget();

private slots:
    void onRowChanged(QModelIndex, QModelIndex);

    void onImportCertButtonClicked();
    void importCertificates(const QStringList &arg);
    void onSyncCaButtonClicked();
    void onAddCertificateButtonClicked();
    void onAddRequestButtonClicked();
    void onRemoveButtonClicked();
    void onDoubleClicked(QModelIndex);

    void onGenerateFinished(MediaNet::Utils::BoolReply * reply);

    void showCertificateDialog(MediaNet::Security::CertificateReply * reply);
    void showRequestDialog(MediaNet::Security::RequestReply * reply);
    void subscribe(MediaNet::Security::Request request);
    void onSubscribeFinished(MediaNet::Security::CertificateReply * reply);
    void onAddCertificateFinished(MediaNet::Utils::BoolReply *reply, const QByteArray & serialNumber);
    void onRemoveRequestFinished(MediaNet::Utils::BoolReply *reply);
    void onAddCertificateFinished(MediaNet::Utils::BoolReply *reply);
    void onImportEnd(int flag);
private:
    void showWaitDialog();
    void hideWaitDialog();

private:
    QSharedPointer<MediaNet::System> mSystem;
    QSharedPointer<MediaNet::Security::IKeyStorage> mKeyStorage;
    QSharedPointer<MediaNet::Security::IRequestStorage> mRequestStorage;
    QSharedPointer<MediaNet::Security::ICertificateStorage> mCertificateStorage;
    QSharedPointer<MediaNet::Security::IGenerator> mGenerator;
    QSharedPointer<MediaNet::Vpn::IVpnManager> mVpnManager;

    CertificateModel mCertificateModel;

    QTableView mTableView;
    QPushButton mAddSelfSignedCertButton;
    QPushButton mAddRequestButton;
    QPushButton mSyncButton;
    QPushButton mRemoveButton;
    QPushButton mImportCert;

    QDialog *mWaitDialog = nullptr;
};


