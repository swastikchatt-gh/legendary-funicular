#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QListWidget>
#include <QListWidgetItem>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QMessageBox>
#include <QInputDialog>
#include <QTimer>
#include <QDateTime>
#include <QUuid>
#include <QFile>
#include <QDataStream>
#include <QByteArray>
#include <QMap>
#include <QDir>
#include <QClipboard>
#include <QLocale>

#include <sodium.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <cstring>
#include <limits>
#include <string_view>

using namespace std::string_view_literals;

// ==================== SecureRandom (mbedTLS) ====================
class SecureRandom {
public:
    SecureRandom() {
        mbedtls_entropy_init(&m_entropy);
        mbedtls_ctr_drbg_init(&m_drbg);
        const char* pers = "password_manager";
        int ret = mbedtls_ctr_drbg_seed(&m_drbg,
                                        mbedtls_entropy_func,
                                        &m_entropy,
                                        reinterpret_cast<const unsigned char*>(pers),
                                        std::strlen(pers));
        if (ret != 0) {
            mbedtls_entropy_free(&m_entropy);
            throw std::runtime_error("Failed to seed CTR_DRBG");
        }
    }

    ~SecureRandom() {
        mbedtls_ctr_drbg_free(&m_drbg);
        mbedtls_entropy_free(&m_entropy);
    }

    void randomBytes(unsigned char* out, size_t len) {
        if (mbedtls_ctr_drbg_random(&m_drbg, out, len) != 0)
            throw std::runtime_error("Random generation failed");
    }

    size_t uniformInt(size_t max) {
        if (max == 0) return 0;
        if (max <= 256) {
            unsigned char byte;
            do { randomBytes(&byte, 1); } while (byte >= 256 - (256 % max));
            return byte % max;
        } else {
            constexpr size_t max_usable = std::numeric_limits<size_t>::max();
            size_t limit = max_usable - (max_usable % max);
            size_t val;
            do { randomBytes(reinterpret_cast<unsigned char*>(&val), sizeof(val)); }
            while (val >= limit);
            return val % max;
        }
    }

private:
    mbedtls_entropy_context m_entropy;
    mbedtls_ctr_drbg_context m_drbg;
};

// Global random generator (initialized in main)
static SecureRandom *g_rng = nullptr;

// ==================== PasswordEntry Struct ====================
struct PasswordEntry {
    QString id;
    QString title;
    QString username;
    QString password;
    QString url;
    QString notes;
    QDateTime created;
    QDateTime modified;
};

// ==================== Encryption (libsodium) ====================
class Encryption {
public:
    static bool encrypt(const QByteArray &plaintext, const QString &masterPass,
                        QByteArray &ciphertext) {
        if (!g_rng) return false;

        QByteArray salt(32, Qt::Uninitialized);
        QByteArray nonce(12, Qt::Uninitialized);
        g_rng->randomBytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size());
        g_rng->randomBytes(reinterpret_cast<unsigned char*>(nonce.data()), nonce.size());

        QByteArray key(32, Qt::Uninitialized);
        QByteArray pwdUtf8 = masterPass.toUtf8();

        if (crypto_pwhash(reinterpret_cast<unsigned char*>(key.data()), key.size(),
                          pwdUtf8.constData(), pwdUtf8.size(),
                          reinterpret_cast<const unsigned char*>(salt.constData()),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE,
                          crypto_pwhash_ALG_ARGON2ID13) != 0) {
            sodium_memzero(key.data(), key.size());
            sodium_memzero(pwdUtf8.data(), pwdUtf8.size());
            return false;
        }

        size_t ctLen = plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES;
        QByteArray encrypted(ctLen, Qt::Uninitialized);
        unsigned long long actualCtLen;

        if (crypto_aead_chacha20poly1305_ietf_encrypt(
                reinterpret_cast<unsigned char*>(encrypted.data()), &actualCtLen,
                reinterpret_cast<const unsigned char*>(plaintext.constData()), plaintext.size(),
                nullptr, 0, nullptr,
                reinterpret_cast<const unsigned char*>(nonce.constData()),
                reinterpret_cast<const unsigned char*>(key.data())) != 0) {
            sodium_memzero(key.data(), key.size());
            sodium_memzero(pwdUtf8.data(), pwdUtf8.size());
            return false;
        }

        ciphertext.clear();
        ciphertext.append(salt);
        ciphertext.append(nonce);
        ciphertext.append(encrypted);

        sodium_memzero(key.data(), key.size());
        sodium_memzero(pwdUtf8.data(), pwdUtf8.size());
        return true;
    }

    static bool decrypt(const QByteArray &ciphertext, const QString &masterPass,
                        QByteArray &plaintext) {
        if (ciphertext.size() < 32 + 12 + 16) return false;

        QByteArray salt = ciphertext.left(32);
        QByteArray nonce = ciphertext.mid(32, 12);
        QByteArray encrypted = ciphertext.mid(44);

        QByteArray key(32, Qt::Uninitialized);
        QByteArray pwdUtf8 = masterPass.toUtf8();

        if (crypto_pwhash(reinterpret_cast<unsigned char*>(key.data()), key.size(),
                          pwdUtf8.constData(), pwdUtf8.size(),
                          reinterpret_cast<const unsigned char*>(salt.constData()),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE,
                          crypto_pwhash_ALG_ARGON2ID13) != 0) {
            sodium_memzero(key.data(), key.size());
            sodium_memzero(pwdUtf8.data(), pwdUtf8.size());
            return false;
        }

        size_t maxPtLen = encrypted.size() - crypto_aead_chacha20poly1305_ietf_ABYTES;
        plaintext.resize(maxPtLen);
        unsigned long long actualPtLen;

        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                reinterpret_cast<unsigned char*>(plaintext.data()), &actualPtLen,
                nullptr,
                reinterpret_cast<const unsigned char*>(encrypted.constData()), encrypted.size(),
                nullptr, 0,
                reinterpret_cast<const unsigned char*>(nonce.constData()),
                reinterpret_cast<const unsigned char*>(key.data())) != 0) {
            sodium_memzero(key.data(), key.size());
            sodium_memzero(pwdUtf8.data(), pwdUtf8.size());
            return false;
        }

        plaintext.resize(actualPtLen);
        sodium_memzero(key.data(), key.size());
        sodium_memzero(pwdUtf8.data(), pwdUtf8.size());
        return true;
    }
};

// ==================== PasswordDatabase ====================
class PasswordDatabase {
public:
    PasswordDatabase() = default;

    bool load(const QString &filename, const QString &masterPass) {
        QFile file(filename);
        if (!file.open(QIODevice::ReadOnly)) return false;
        QByteArray data = file.readAll();
        file.close();

        QByteArray decrypted;
        if (!Encryption::decrypt(data, masterPass, decrypted)) return false;

        m_entries.clear();
        QDataStream stream(decrypted);
        stream.setVersion(QDataStream::Qt_6_0);
        int count;
        stream >> count;
        for (int i = 0; i < count; ++i) {
            PasswordEntry entry;
            stream >> entry.id >> entry.title >> entry.username >> entry.password
                   >> entry.url >> entry.notes >> entry.created >> entry.modified;
            m_entries.insert(entry.id, entry);
        }

        sodium_memzero(decrypted.data(), decrypted.size());
        m_encryptedData = data;
        return true;
    }

    bool save(const QString &filename, const QString &masterPass) {
        QByteArray data;
        QDataStream stream(&data, QIODevice::WriteOnly);
        stream.setVersion(QDataStream::Qt_6_0);
        stream << m_entries.size();
        for (const auto &e : m_entries) {
            stream << e.id << e.title << e.username << e.password
                   << e.url << e.notes << e.created << e.modified;
        }

        QByteArray encrypted;
        if (!Encryption::encrypt(data, masterPass, encrypted)) return false;

        QFile file(filename);
        if (!file.open(QIODevice::WriteOnly)) return false;
        file.write(encrypted);
        file.close();

        m_encryptedData = encrypted;
        return true;
    }

    bool changeMasterPassword(const QString &oldPass, const QString &newPass) {
        if (m_encryptedData.isEmpty()) return false;
        QByteArray decrypted;
        if (!Encryption::decrypt(m_encryptedData, oldPass, decrypted)) return false;
        QByteArray newEncrypted;
        if (!Encryption::encrypt(decrypted, newPass, newEncrypted)) return false;
        m_encryptedData = newEncrypted;
        sodium_memzero(decrypted.data(), decrypted.size());
        return true;
    }

    void addEntry(const PasswordEntry &entry) {
        m_entries.insert(entry.id, entry);
    }

    void updateEntry(const PasswordEntry &entry) {
        if (m_entries.contains(entry.id))
            m_entries[entry.id] = entry;
    }

    void deleteEntry(const QString &id) {
        m_entries.remove(id);
    }

    PasswordEntry getEntry(const QString &id) const {
        return m_entries.value(id);
    }

    QList<PasswordEntry> getAllEntries() const {
        return m_entries.values();
    }

    void clear() {
        m_entries.clear();
        m_encryptedData.clear();
    }

    bool verifyMasterPassword(const QString &masterPass) const {
        if (m_encryptedData.isEmpty()) return false;
        QByteArray dummy;
        return Encryption::decrypt(m_encryptedData, masterPass, dummy);
    }

private:
    QMap<QString, PasswordEntry> m_entries;
    QByteArray m_encryptedData;
};

// ==================== PasswordGenerator ====================
class PasswordGenerator {
public:
    static QString generate(int length = 16) {
        if (!g_rng) return QString();
        if (length < 4) length = 4;

        const std::string_view upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"sv;
        const std::string_view lower = "abcdefghijklmnopqrstuvwxyz"sv;
        const std::string_view digits = "0123456789"sv;
        const std::string_view symbols = "!@#$%^&*()-_=+[]{}<>?/|"sv;

        std::string all = std::string(upper) + std::string(lower) +
                          std::string(digits) + std::string(symbols);

        std::string pwd;
        pwd.reserve(length);
        pwd += upper[g_rng->uniformInt(upper.size())];
        pwd += lower[g_rng->uniformInt(lower.size())];
        pwd += digits[g_rng->uniformInt(digits.size())];
        pwd += symbols[g_rng->uniformInt(symbols.size())];
        while (pwd.size() < static_cast<size_t>(length))
            pwd += all[g_rng->uniformInt(all.size())];

        // Fisher‑Yates shuffle
        for (size_t i = pwd.size() - 1; i > 0; --i) {
            size_t j = g_rng->uniformInt(i + 1);
            std::swap(pwd[i], pwd[j]);
        }
        return QString::fromStdString(pwd);
    }
};

// ==================== AddEntryDialog ====================
class AddEntryDialog : public QDialog {
    Q_OBJECT
public:
    explicit AddEntryDialog(QWidget *parent = nullptr, const PasswordEntry &entry = PasswordEntry())
        : QDialog(parent) {
        setupUI();
        if (!entry.id.isEmpty()) {
            m_titleEdit->setText(entry.title);
            m_usernameEdit->setText(entry.username);
            m_passwordEdit->setText(entry.password);
            m_urlEdit->setText(entry.url);
            m_notesEdit->setPlainText(entry.notes);
        }
    }

    PasswordEntry getEntry() const {
        PasswordEntry e;
        e.title = m_titleEdit->text().trimmed();
        e.username = m_usernameEdit->text().trimmed();
        e.password = m_passwordEdit->text();
        e.url = m_urlEdit->text().trimmed();
        e.notes = m_notesEdit->toPlainText().trimmed();
        return e;
    }

private slots:
    void generatePassword() {
        QString pwd = PasswordGenerator::generate();
        m_passwordEdit->setText(pwd);
        QApplication::clipboard()->setText(pwd);
        QTimer::singleShot(30000, []{ QApplication::clipboard()->clear(); }); // auto‑clear
    }

private:
    void setupUI() {
        setWindowTitle(tr("Add/Edit Entry"));
        QVBoxLayout *mainLayout = new QVBoxLayout(this);

        QFormLayout *formLayout = new QFormLayout;
        m_titleEdit = new QLineEdit;
        m_usernameEdit = new QLineEdit;
        m_passwordEdit = new QLineEdit;
        m_passwordEdit->setEchoMode(QLineEdit::Password);
        m_generateButton = new QPushButton(tr("Generate"));
        connect(m_generateButton, &QPushButton::clicked, this, &AddEntryDialog::generatePassword);

        QHBoxLayout *passwordLayout = new QHBoxLayout;
        passwordLayout->addWidget(m_passwordEdit);
        passwordLayout->addWidget(m_generateButton);

        m_urlEdit = new QLineEdit;
        m_notesEdit = new QTextEdit;

        formLayout->addRow(tr("Title:"), m_titleEdit);
        formLayout->addRow(tr("Username:"), m_usernameEdit);
        formLayout->addRow(tr("Password:"), passwordLayout);
        formLayout->addRow(tr("URL:"), m_urlEdit);
        formLayout->addRow(tr("Notes:"), m_notesEdit);

        mainLayout->addLayout(formLayout);

        QHBoxLayout *buttonLayout = new QHBoxLayout;
        m_okButton = new QPushButton(tr("OK"));
        m_cancelButton = new QPushButton(tr("Cancel"));
        connect(m_okButton, &QPushButton::clicked, this, &QDialog::accept);
        connect(m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
        buttonLayout->addStretch();
        buttonLayout->addWidget(m_okButton);
        buttonLayout->addWidget(m_cancelButton);

        mainLayout->addLayout(buttonLayout);
    }

    QLineEdit *m_titleEdit;
    QLineEdit *m_usernameEdit;
    QLineEdit *m_passwordEdit;
    QPushButton *m_generateButton;
    QLineEdit *m_urlEdit;
    QTextEdit *m_notesEdit;
    QPushButton *m_okButton;
    QPushButton *m_cancelButton;
};

// ==================== MainWindow ====================
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr) : QMainWindow(parent), m_unlocked(false) {
        setupUI();
        m_lockTimer = new QTimer(this);
        m_lockTimer->setSingleShot(true);
        connect(m_lockTimer, &QTimer::timeout, this, &MainWindow::lock);

        // Start locked – will prompt for password after show
        QTimer::singleShot(0, this, &MainWindow::onActionUnlock);
    }

    ~MainWindow() {
        if (m_unlocked) lock();
    }

private slots:
    void onAddEntry() {
        if (!checkUnlocked()) return;
        AddEntryDialog dlg(this);
        if (dlg.exec() == QDialog::Accepted) {
            PasswordEntry entry = dlg.getEntry();
            entry.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
            entry.created = QDateTime::currentDateTime();
            entry.modified = entry.created;
            m_database.addEntry(entry);
            saveDatabase();
            updateEntryList(m_searchEdit->text());
            m_lockTimer->start(300000); // 5 min
        }
    }

    void onEditEntry() {
        if (!checkUnlocked()) return;
        QListWidgetItem *item = m_entryList->currentItem();
        if (!item) {
            QMessageBox::warning(this, tr("Error"), tr("No entry selected."));
            return;
        }
        QString id = item->data(Qt::UserRole).toString();
        PasswordEntry entry = m_database.getEntry(id);
        AddEntryDialog dlg(this, entry);
        if (dlg.exec() == QDialog::Accepted) {
            PasswordEntry updated = dlg.getEntry();
            updated.id = id;
            updated.created = entry.created;
            updated.modified = QDateTime::currentDateTime();
            m_database.updateEntry(updated);
            saveDatabase();
            updateEntryList(m_searchEdit->text());
            m_lockTimer->start(300000);
        }
    }

    void onDeleteEntry() {
        if (!checkUnlocked()) return;
        QListWidgetItem *item = m_entryList->currentItem();
        if (!item) {
            QMessageBox::warning(this, tr("Error"), tr("No entry selected."));
            return;
        }
        if (QMessageBox::question(this, tr("Confirm"), tr("Delete this entry?")) == QMessageBox::Yes) {
            QString id = item->data(Qt::UserRole).toString();
            m_database.deleteEntry(id);
            saveDatabase();
            updateEntryList(m_searchEdit->text());
            clearDetails();
            m_lockTimer->start(300000);
        }
    }

    void onSearch(const QString &text) {
        if (!m_unlocked) return;
        updateEntryList(text);
    }

    void onListCurrentItemChanged(QListWidgetItem *current, QListWidgetItem *previous) {
        Q_UNUSED(previous);
        if (!current || !m_unlocked) {
            clearDetails();
            return;
        }
        QString id = current->data(Qt::UserRole).toString();
        PasswordEntry entry = m_database.getEntry(id);
        showEntryDetails(entry);
        m_lockTimer->start(300000);
    }

    void onLockTimerTimeout() { lock(); }
    void onActionLock() { lock(); }

    void onActionUnlock() {
        if (m_unlocked) return;
        bool ok;
        QString masterPass = QInputDialog::getText(this, tr("Unlock Database"),
                                                   tr("Master password:"), QLineEdit::Password, "", &ok);
        if (!ok) return;
        unlock(masterPass);
    }

    void onActionChangeMasterPassword() {
        if (!checkUnlocked()) return;
        bool ok;
        QString oldPass = QInputDialog::getText(this, tr("Change Master Password"),
                                                tr("Current password:"), QLineEdit::Password, "", &ok);
        if (!ok) return;
        if (!m_database.verifyMasterPassword(oldPass)) {
            QMessageBox::critical(this, tr("Error"), tr("Incorrect password."));
            return;
        }
        QString newPass = QInputDialog::getText(this, tr("Change Master Password"),
                                                tr("New password:"), QLineEdit::Password, "", &ok);
        if (!ok || newPass.isEmpty()) return;
        QString confirm = QInputDialog::getText(this, tr("Change Master Password"),
                                                tr("Confirm new password:"), QLineEdit::Password, "", &ok);
        if (!ok || newPass != confirm) {
            QMessageBox::critical(this, tr("Error"), tr("Passwords do not match."));
            return;
        }
        if (m_database.changeMasterPassword(oldPass, newPass)) {
            m_masterPassword = newPass;  // store new for future saves
            saveDatabase();
            QMessageBox::information(this, tr("Success"), tr("Master password changed."));
        } else {
            QMessageBox::critical(this, tr("Error"), tr("Failed to change password."));
        }
        m_lockTimer->start(300000);
    }

    void onActionExit() { close(); }

private:
    void setupUI() {
        setWindowTitle(tr("Password Manager"));
        resize(800, 600);

        QWidget *central = new QWidget(this);
        QHBoxLayout *mainLayout = new QHBoxLayout(central);

        // Left panel
        QWidget *leftPanel = new QWidget;
        QVBoxLayout *leftLayout = new QVBoxLayout(leftPanel);
        m_searchEdit = new QLineEdit;
        m_searchEdit->setPlaceholderText(tr("Search..."));
        connect(m_searchEdit, &QLineEdit::textChanged, this, &MainWindow::onSearch);
        m_entryList = new QListWidget;
        connect(m_entryList, &QListWidget::currentItemChanged,
                this, &MainWindow::onListCurrentItemChanged);
        leftLayout->addWidget(m_searchEdit);
        leftLayout->addWidget(m_entryList);

        // Right panel
        QWidget *rightPanel = new QWidget;
        QVBoxLayout *rightLayout = new QVBoxLayout(rightPanel);
        m_detailsDisplay = new QTextEdit;
        m_detailsDisplay->setReadOnly(true);

        QHBoxLayout *buttonLayout = new QHBoxLayout;
        m_addButton = new QPushButton(tr("Add"));
        m_editButton = new QPushButton(tr("Edit"));
        m_deleteButton = new QPushButton(tr("Delete"));
        buttonLayout->addWidget(m_addButton);
        buttonLayout->addWidget(m_editButton);
        buttonLayout->addWidget(m_deleteButton);
        buttonLayout->addStretch();

        rightLayout->addWidget(m_detailsDisplay);
        rightLayout->addLayout(buttonLayout);

        mainLayout->addWidget(leftPanel, 1);
        mainLayout->addWidget(rightPanel, 2);
        setCentralWidget(central);

        // Menu
        QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
        QAction *lockAction = fileMenu->addAction(tr("Lock"));
        QAction *unlockAction = fileMenu->addAction(tr("Unlock"));
        QAction *changeMasterAction = fileMenu->addAction(tr("Change Master Password"));
        fileMenu->addSeparator();
        QAction *exitAction = fileMenu->addAction(tr("Exit"));

        connect(lockAction, &QAction::triggered, this, &MainWindow::onActionLock);
        connect(unlockAction, &QAction::triggered, this, &MainWindow::onActionUnlock);
        connect(changeMasterAction, &QAction::triggered, this, &MainWindow::onActionChangeMasterPassword);
        connect(exitAction, &QAction::triggered, this, &MainWindow::onActionExit);

        connect(m_addButton, &QPushButton::clicked, this, &MainWindow::onAddEntry);
        connect(m_editButton, &QPushButton::clicked, this, &MainWindow::onEditEntry);
        connect(m_deleteButton, &QPushButton::clicked, this, &MainWindow::onDeleteEntry);
    }

    void updateEntryList(const QString &filter) {
        m_entryList->clear();
        if (!m_unlocked) return;
        for (const auto &entry : m_database.getAllEntries()) {
            if (filter.isEmpty() ||
                entry.title.contains(filter, Qt::CaseInsensitive) ||
                entry.username.contains(filter, Qt::CaseInsensitive) ||
                entry.url.contains(filter, Qt::CaseInsensitive) ||
                entry.notes.contains(filter, Qt::CaseInsensitive)) {
                QListWidgetItem *item = new QListWidgetItem(entry.title);
                item->setData(Qt::UserRole, entry.id);
                m_entryList->addItem(item);
            }
        }
        if (m_entryList->count() > 0)
            m_entryList->setCurrentRow(0);
        else
            clearDetails();
    }

    void showEntryDetails(const PasswordEntry &entry) {
        QString text = QString(
            "<b>Title:</b> %1<br>"
            "<b>Username:</b> %2<br>"
            "<b>Password:</b> %3<br>"
            "<b>URL:</b> %4<br>"
            "<b>Notes:</b><br>%5<br><br>"
            "<b>Created:</b> %6<br>"
            "<b>Modified:</b> %7"
        ).arg(entry.title.toHtmlEscaped())
         .arg(entry.username.toHtmlEscaped())
         .arg(entry.password.toHtmlEscaped())
         .arg(entry.url.toHtmlEscaped())
         .arg(entry.notes.toHtmlEscaped().replace("\n", "<br>"))
         .arg(QLocale::system().toString(entry.created, QLocale::ShortFormat))
         .arg(QLocale::system().toString(entry.modified, QLocale::ShortFormat));
        m_detailsDisplay->setHtml(text);
    }

    void clearDetails() {
        m_detailsDisplay->clear();
    }

    void lock() {
        if (!m_unlocked) return;
        // Zero master password from memory
        sodium_memzero(m_masterPassword.data(), m_masterPassword.size() * sizeof(QChar));
        m_masterPassword.clear();
        m_database.clear();
        m_unlocked = false;
        m_entryList->clear();
        clearDetails();
        m_lockTimer->stop();
        QMessageBox::information(this, tr("Locked"), tr("Database locked."));
    }

    void unlock(const QString &masterPass) {
        QString filename = QDir::home().filePath(".password_manager.dat");
        if (!m_database.load(filename, masterPass)) {
            if (!QFile::exists(filename)) {
                // Create new database
                if (m_database.save(filename, masterPass)) {
                    m_unlocked = true;
                    m_masterPassword = masterPass;
                    updateEntryList("");   // ← FIXED
                    m_lockTimer->start(300000);
                    QMessageBox::information(this, tr("Success"), tr("New database created and unlocked."));
                    return;
                }
            }
            QMessageBox::critical(this, tr("Error"), tr("Failed to unlock. Wrong password or corrupted file."));
            return;
        }
        m_unlocked = true;
        m_masterPassword = masterPass;
        updateEntryList("");   // ← FIXED
        m_lockTimer->start(300000);
        QMessageBox::information(this, tr("Success"), tr("Database unlocked."));
    }

    void saveDatabase() {
        if (!m_unlocked || m_masterPassword.isEmpty()) return;
        QString filename = QDir::home().filePath(".password_manager.dat");
        m_database.save(filename, m_masterPassword);
    }

    bool checkUnlocked() {
        if (!m_unlocked) {
            QMessageBox::warning(this, tr("Locked"), tr("Database is locked. Please unlock first."));
            return false;
        }
        return true;
    }

    QListWidget *m_entryList;
    QLineEdit *m_searchEdit;
    QTextEdit *m_detailsDisplay;
    QPushButton *m_addButton, *m_editButton, *m_deleteButton;
    PasswordDatabase m_database;
    QString m_masterPassword;
    bool m_unlocked;
    QTimer *m_lockTimer;
};

// ==================== main ====================
int main(int argc, char *argv[]) {
    QApplication a(argc, argv);

    if (sodium_init() < 0) {
        QMessageBox::critical(nullptr, "Fatal Error", "Failed to initialize libsodium.");
        return 1;
    }

    try {
        g_rng = new SecureRandom();
    } catch (const std::exception &e) {
        QMessageBox::critical(nullptr, "Fatal Error", e.what());
        return 1;
    }

    MainWindow w;
    w.show();

    int ret = a.exec();

    delete g_rng;
    return ret;
}

#include "main.moc"
