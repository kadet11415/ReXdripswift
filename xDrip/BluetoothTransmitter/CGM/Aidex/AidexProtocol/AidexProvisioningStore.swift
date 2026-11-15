import Foundation
import Security
import CryptoKit

/// Персистентность CN-сессии (аппачкун: phone + token) и provisioned-материала
/// сенсоров (`getSnConfig`). iOS-порт 1:1 от JugglucoNG `AiDexProvisioningStore`
/// (§2.2/§3/§24): token/зачёт — в Keychain (не коммитить в файл), материал —
/// Keychain-записи `material_<sha256(BARE)>` с JSON `{secret, iv}` (base64).
///
/// Export/import-формат 1:1 от `AiDexPairingMaterialFile` (JSON
/// `juggluco-aidex-pairing-material` v1).
final class AidexProvisioningStore {

    // MARK: - Key-value storage (injectable for tests)

    protocol KeyValue: AnyObject {
        func string(forKey key: String) -> String?
        func setString(_ v: String, forKey key: String) -> Bool
        func remove(_ key: String)
    }

    /// Keychain generic-password хранилище.
    final class KeychainKeyValue: KeyValue {
        private let service: String
        init(service: String) { self.service = service }

        func string(forKey key: String) -> String? {
            let query: [String: Any] = [
                String(kSecClass): String(kSecClassGenericPassword),
                String(kSecAttrService): service,
                String(kSecAttrAccount): key,
                String(kSecReturnData): true,
                String(kSecMatchLimit): String(kSecMatchLimitOne),
            ]
            guard let item = SecItemCopyMatching(query as CFDictionary, nil) as? [String: Any],
                  let data = item[String(kSecValueData)] as? Data,
                  let v = String(data: data, encoding: .utf8) else { return nil }
            return v
        }

        func setString(_ v: String, forKey key: String) -> Bool {
            remove(key)
            let attrs: [String: Any] = [
                String(kSecClass): String(kSecClassGenericPassword),
                String(kSecAttrService): service,
                String(kSecAttrAccount): key,
                String(kSecValueData): Data(v.utf8),
                String(kSecAttrAccessible): String(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            ]
            return SecItemAdd(attrs as CFDictionary, nil) == errSecSuccess
        }

        func remove(_ key: String) {
            let query: [String: Any] = [
                String(kSecClass): String(kSecClassGenericPassword),
                String(kSecAttrService): service,
                String(kSecAttrAccount): key,
            ]
            _ = SecItemDelete(query as CFDictionary)
        }
    }

    /// Память (тесты).
    final class MemoryKeyValue: KeyValue {
        private var values: [String: String] = [:]
        private let lock = NSLock()
        func string(forKey key: String) -> String? {
            lock.lock(); defer { lock.unlock() }
            return values[key]
        }
        func setString(_ v: String, forKey key: String) -> Bool {
            lock.lock(); defer { lock.unlock() }
            values[key] = v
            return true
        }
        func remove(_ key: String) {
            lock.lock(); defer { lock.unlock() }
            values[key] = nil
        }
    }

    // MARK: - Keys (Kotlin 1:1)

    private static let tokenKey = "account_token"
    private static let accountKey = "account_label"
    private static let materialPrefix = "material_"

    private let store: KeyValue
    let service: String

    init(service: String = "aidex_cn_provisioning", store: KeyValue? = nil) {
        self.service = service
        self.store = store ?? KeychainKeyValue(service: service)
    }

    static let shared = AidexProvisioningStore()

    // MARK: - CN session

    func hasSession() -> Bool { !token().isEmpty }

    func token() -> String { store.string(forKey: Self.tokenKey) ?? "" }

    /// `+86<11 цифр>`-label аккаунта (Kotlin `accountLabel`).
    func accountLabel() -> String { store.string(forKey: Self.accountKey) ?? "" }

    @discardableResult
    func saveSession(accountLabel: String, token: String) -> Bool {
        guard !token.isEmpty else { return false }
        _ = store.setString(token, forKey: Self.tokenKey)
        _ = store.setString(accountLabel, forKey: Self.accountKey)
        return true
    }

    func clearSession() {
        store.remove(Self.tokenKey)
        store.remove(Self.accountKey)
    }

    // MARK: - Provisioned material

    private static func materialKey(_ serial: String) -> String {
        let canonical = Self.normalizeSerial(serial) ?? serial.uppercased()
        let digest = SHA256.hash(data: Data(canonical.utf8))
        let hex = Data(digest).map { String(format: "%02x", $0) }.joined()
        return Self.materialPrefix + hex
    }

    /// Канонизация serial'а (Kotlin `AiDexPairingMaterialFile.normalizeSerial`):
    /// bare (strip `X-`/префикса), trim, upper; ровно 8..14 alphanumeric.
    static func normalizeSerial(_ raw: String) -> String? {
        let bare = SerialCrypto.stripPrefix(raw).trimmingCharacters(in: .whitespaces).uppercased()
        guard bare.count >= 8, bare.count <= 14, bare.allSatisfy({ $0.isLetter || $0.isNumber }) else { return nil }
        return bare
    }

    /// Материал для serial'а (Kotlin `loadSaved`).
    func loadSaved(_ serial: String) -> AidexPairingMaterial? {
        let canonical = Self.normalizeSerial(serial)
        guard let canonical, let value = store.string(forKey: Self.materialKey(canonical)), !value.isEmpty else { return nil }
        guard let data = value.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let secret = Self.decodeMaterial(json["secret"] as? String ?? ""),
              let iv = Self.decodeMaterial(json["iv"] as? String ?? "") else { return nil }
        return AidexPairingMaterial(secret: secret, iv: iv)
    }

    func hasSaved(_ serial: String) -> Bool { loadSaved(serial) != nil }

    /// Store ровно полного материала (Kotlin `saveAndInstall` — без install,
    /// который здесь делает `installSaved` при старте key-exchange).
    @discardableResult
    func saveAndInstall(_ serial: String, secret: Data, iv: Data) -> Bool {
        guard secret.count == 16, iv.count == 16 else { return false }
        let canonical = Self.normalizeSerial(serial) ?? ""
        guard !canonical.isEmpty else { return false }
        let json: [String: String] = [
            "secret": secret.base64EncodedString(),
            "iv": iv.base64EncodedString(),
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: json),
              let value = String(data: data, encoding: .utf8) else { return false }
        return store.setString(value, forKey: Self.materialKey(canonical))
    }

    /// Установить сохранённый материал перед построением F001 key-exchange
    /// (Kotlin `installSaved` — `maybeUseProvisionedPairingMaterial`).
    func installSaved(_ serial: String) -> Bool {
        loadSaved(serial) != nil
    }

    func clearMaterial(_ serial: String) {
        let canonical = Self.normalizeSerial(serial) ?? ""
        guard !canonical.isEmpty else { return }
        store.remove(Self.materialKey(canonical))
    }

    private static func decodeMaterial(_ encoded: String) -> Data? {
        guard let data = Data(base64Encoded: encoded), data.count == 16 else { return nil }
        return data
    }

    // MARK: - Export / import (AiDexPairingMaterialFile 1:1)

    static let exportFormat = "juggluco-aidex-pairing-material"
    static let exportVersion = 1

    static func encodeExport(_ serial: String, secret: Data, iv: Data) -> String? {
        guard let normalized = normalizeSerial(serial), secret.count == 16, iv.count == 16 else { return nil }
        let object: [String: Any] = [
            "format": exportFormat,
            "version": exportVersion,
            "sensorSerial": normalized,
            "publicKey": secret.base64EncodedString(),
            "communicationKey": iv.base64EncodedString(),
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func decodeExport(_ jsonText: String) -> (serial: String, secret: Data, iv: Data)? {
        guard let data = jsonText.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        let format = json["format"] as? String ?? ""
        if !format.isEmpty, format != exportFormat { return nil }
        guard let version = (json["version"] as? NSNumber)?.intValue, version == exportVersion else { return nil }
        let serialRaw = (json["sensorSerial"] as? String).flatMap { !$0.isEmpty ? $0 : nil }
            ?? (json["deviceSn"] as? String)
            ?? (json["serial"] as? String) ?? ""
        guard let serial = normalizeSerial(serialRaw) else { return nil }
        let secretField = (json["publicKey"] as? String).flatMap { !$0.isEmpty ? $0 : nil } ?? (json["secret"] as? String) ?? ""
        let ivField = (json["communicationKey"] as? String).flatMap { !$0.isEmpty ? $0 : nil } ?? (json["iv"] as? String) ?? ""
        guard let secret = decodeMaterial(secretField), let iv = decodeMaterial(ivField) else { return nil }
        return (serial, secret, iv)
    }

    func exportJson(_ serial: String) -> String? {
        guard let material = loadSaved(serial) else { return nil }
        guard let canonical = Self.normalizeSerial(serial) else { return nil }
        return Self.encodeExport(canonical, secret: material.secret, iv: material.iv)
    }

    /// Импорт JSON: валидируем → save → вернём serial (Kotlin `importJson`).
    func importJson(_ jsonText: String) -> String? {
        guard let parsed = Self.decodeExport(jsonText) else { return nil }
        return saveAndInstall(parsed.serial, secret: parsed.secret, iv: parsed.iv) ? parsed.serial : nil
    }
}
