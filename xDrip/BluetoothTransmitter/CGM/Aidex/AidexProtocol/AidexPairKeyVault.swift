import Foundation
import Security
import CryptoKit

/// Редундантное app-private хранение стабильного AiDex PAIR-credential'а.
///
/// iOS-адаптер от Android-дизайна 3-tier (Kotlin `AiDexPairKeyVault`, §19/§24):
/// primary = Keychain (generic password, аккаунт `pairKey_v1_<BARE>`),
/// recovery = текстовый файл-копия в Application Support (тот же encoded
/// payload, что и в Keychain-value). Конфликт копий — никогда не угадывать:
/// `load` возвращает nil.
///
/// Запись: `saveIfAbsent` — никогда не затирает чужой ключ;
/// `saveValidated` — заменяет только ключ, который только что расшифровал
/// CRC-valid live-фрейм (единственная достаточная доказательная база).
final class AiDexPairKeyVault {

    enum ImportResult { case saved, alreadyPresent, conflict, invalid }

    // MARK: - Stores (injectable for tests)

    /// Одна копия = encoded payload-стринг (формат `AiDexPairKeyBackup`).
    protocol PairKeyStore: AnyObject {
        func read(_ account: String) -> String?
        func write(_ account: String, _ payload: String) -> Bool
        func remove(_ account: String) -> Bool
    }

    /// Keychain-копия (primary).
    final class KeychainPairKeyStore: PairKeyStore {
        private let service = "AiDexPairKeyVault"

        func read(_ account: String) -> String? {
            let query: [String: Any] = [
                String(kSecClass): String(kSecClassGenericPassword),
                String(kSecAttrService): service,
                String(kSecAttrAccount): account,
                String(kSecReturnData): true,
                String(kSecMatchLimit): String(kSecMatchLimitOne),
            ]
            guard let item = SecItemCopyMatching(query as CFDictionary, nil)
                    as? [String: Any],
                  let data = item[String(kSecValueData)] as? Data,
                  let value = String(data: data, encoding: .utf8) else { return nil }
            return value
        }

        func write(_ account: String, _ payload: String) -> Bool {
            remove(account)
            let attrs: [String: Any] = [
                String(kSecClass): String(kSecClassGenericPassword),
                String(kSecAttrService): service,
                String(kSecAttrAccount): account,
                String(kSecValueData): Data(payload.utf8),
                String(kSecAttrAccessible): String(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            ]
            return SecItemAdd(attrs as CFDictionary, nil) == errSecSuccess
        }

        func remove(_ account: String) -> Bool {
            let query: [String: Any] = [
                String(kSecClass): String(kSecClassGenericPassword),
                String(kSecAttrService): service,
                String(kSecAttrAccount): account,
            ]
            let status = SecItemDelete(query as CFDictionary)
            return status == errSecSuccess || status == errSecItemNotFound
        }
    }

    /// Файл-копия (recovery) в `Application Support/AidexPairKeyVault/`.
    final class FilePairKeyStore: PairKeyStore {
        private let directory: URL
        init(directory: URL = FilePairKeyStore.defaultDirectory) {
            self.directory = directory
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }

        static var defaultDirectory: URL {
            let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            let dir = (base ?? URL(fileURLWithPath: NSHomeDirectory())).appendingPathComponent("AidexPairKeyVault", isDirectory: true)
            return dir
        }

        private func url(for account: String) -> URL {
            directory.appendingPathComponent(account.replacingOccurrences(of: "/", with: "_") + ".txt")
        }

        func read(_ account: String) -> String? {
            guard let data = try? Data(contentsOf: url(for: account)) else { return nil }
            return String(data: data, encoding: .utf8)
        }

        func write(_ account: String, _ payload: String) -> Bool {
            (try? payload.write(to: url(for: account), atomically: true, encoding: .utf8)) != nil
        }

        func remove(_ account: String) -> Bool {
            let file = url(for: account)
            guard FileManager.default.fileExists(atPath: file.path) else { return true }
            return (try? FileManager.default.removeItem(at: file)) != nil
        }
    }

    // MARK: - Init

    let primary: PairKeyStore
    let recovery: PairKeyStore

    init(primary: PairKeyStore? = nil, recovery: PairKeyStore? = nil) {
        self.primary = primary ?? AiDexPairKeyVault.KeychainPairKeyStore()
        self.recovery = recovery ?? AiDexPairKeyVault.FilePairKeyStore()
    }

    static let shared = AiDexPairKeyVault()

    // MARK: - API

    private func account(_ serial: String) -> String {
        "pairKey_v1_" + AiDexPairKeyBackup.canonicalBareSerial(serial)
    }

    private func readCopies(_ serial: String) -> [Data] {
        let key = account(serial)
        let bare = AiDexPairKeyBackup.canonicalBareSerial(serial)
        return [primary, recovery].compactMap { store in
            guard let payload = store.read(key),
                  let record = AiDexPairKeyBackup.decode(payload),
                  record.bareSerial == bare else {
                print("[AidexPairKeyVault] ignoring corrupt copy for \(bare)")
                return nil
            }
            return record.pairKey
        }
    }

    private func writeCopies(_ serial: String, _ pairKey: Data) -> Bool {
        guard let payload = AiDexPairKeyBackup.encode(serial: serial, pairKey: pairKey) else { return false }
        let key = account(serial)
        let primarySaved = primary.write(key, payload)
        let recoverySaved = recovery.write(key, payload)
        if !primarySaved {
            print("[AidexPairKeyVault] primary copy write failed for \(AiDexPairKeyBackup.canonicalBareSerial(serial))")
        }
        return primarySaved || recoverySaved
    }

    /// load: две копии обязаны совпасть; конфликт → nil (никогда не угадать).
    func load(_ serial: String) -> Data? {
        let copies = readCopies(serial)
        guard !copies.isEmpty else { return nil }
        let seen = Set(copies.map { $0.uppercasedHex })
        guard seen.count == 1 else {
            print("[AidexPairKeyVault] conflicting stored PAIR credentials for \(AiDexPairKeyBackup.canonicalBareSerial(serial)); refusing automatic selection")
            return nil
        }
        return copies.first
    }

    /// `hasSavedPairKey` для `decidePairKeyStartAction`.
    func hasSavedPairKey(_ serial: String) -> Bool {
        load(serial)?.count == AiDexPairKeyBackup.pairKeyBytes
    }

    /// Save только когда другого credential'а нет.
    func saveIfAbsent(_ serial: String, _ pairKey: Data) -> Bool {
        guard pairKey.count == AiDexPairKeyBackup.pairKeyBytes else { return false }
        let bare = AiDexPairKeyBackup.canonicalBareSerial(serial)
        let existing = readCopies(bare)
        if existing.contains(where: { $0 != pairKey }) {
            print("[AidexPairKeyVault] refusing to overwrite a different stored PAIR credential for \(bare)")
            return false
        }
        if existing.count == 2 { return true }
        return writeCopies(bare, pairKey)
    }

    /// Save credential'а, только что расшифровывавшего CRC-valid live-фрейм.
    /// Единственная доказательная база замены: конфликтные копии исцеляются
    /// валидированным ключом (Kotlin `saveValidated`).
    func saveValidated(_ serial: String, _ pairKey: Data) -> Bool {
        guard pairKey.count == AiDexPairKeyBackup.pairKeyBytes else { return false }
        let bare = AiDexPairKeyBackup.canonicalBareSerial(serial)
        let existing = readCopies(bare)
        if existing.count == 2 && existing.allSatisfy({ $0 == pairKey }) { return true }
        if existing.contains(where: { $0 != pairKey }) {
            print("[AidexPairKeyVault] replacing stored PAIR credential for \(bare) with one validated by live data")
        }
        return writeCopies(bare, pairKey)
    }

    /// Clear только после подтверждённого UNPAIR (DELETE_BOND 0x01, §19).
    func clearAfterConfirmedUnpair(_ serial: String) -> Bool {
        clearStoredKey(serial)
    }

    /// Force-удаление (ручное Delete при мёртвом ключе).
    func clearStoredKey(_ serial: String) -> Bool {
        let key = account(serial)
        let primaryCleared = primary.remove(key)
        let recoveryCleared = recovery.remove(key)
        return primaryCleared && recoveryCleared
    }

    /// Экспорт-стринг для cross-device handoff (Kotlin `exportPayload`).
    func exportPayload(_ serial: String) -> String? {
        guard let pairKey = load(serial) else { return nil }
        return AiDexPairKeyBackup.encode(serial: serial, pairKey: pairKey)
    }

    /// Импорт export-стринга (Kotlin `importPayload`).
    func importPayload(_ payload: String) -> ImportResult {
        guard let record = AiDexPairKeyBackup.decode(payload) else { return .invalid }
        let existing = readCopies(record.bareSerial)
        if existing.contains(where: { $0 != record.pairKey }) { return .conflict }
        if !existing.isEmpty && existing.allSatisfy({ $0 == record.pairKey }) {
            saveIfAbsent(record.bareSerial, record.pairKey)
            return .alreadyPresent
        }
        return saveIfAbsent(record.bareSerial, record.pairKey) ? .saved : .conflict
    }

    /// Короткий неразворотимый тег для логов: первые 4 байта SHA-256 (hex).
    static func fingerprint(_ pairKey: Data?) -> String {
        guard let pairKey else { return "none" }
        let digest = SHA256.hash(data: pairKey)
        return Data(digest.prefix(4)).map { String(format: "%02x", $0) }.joined()
    }
}
