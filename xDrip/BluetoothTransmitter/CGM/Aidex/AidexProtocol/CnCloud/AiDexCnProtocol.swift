import Foundation
import CryptoKit
import Security

/// Чистая крипто-часть CN-облака (china.pancares.com): подпись integrity,
/// enveloping через встроенные RSA-1024 ключи приложения (PKCS#1 v1.5),
/// декодирование provisioned-материала.
///
/// Порт 1:1 из JugglucoNG `AiDexCnProtocol` (Kotlin). Ключи и APP_SECRET —
/// встроенные в приложение (не логировать, не писать в отладочные строки
/// с PII-контекстом).
///
/// §24: RSA-1024 PKCS1 (SecKey, `.PKCS1`), MD5 (Crypto) — 1:1.
enum AiDexCnProtocol {

    // APP_SECRET и ключи — 1:1 из `AiDexCnProtocol` (AiDexCnCloudClient.kt).
    // Не выводить в логи.
    private static let appSecret = "4ed6aa2b43a04251b6f78db47f870906"

    /// RSA-1024 public key (X509 DER, base64) — шифрование запросов.
    private static let publicKey = """
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMh1zL8SIgJ+3Cpi5k2DNB9O3/a5XqDhX6d9JxMuQ9PJwYDLU4Qvv4AnAHB3mmiQVaGCqgSjUxBGgH5eG738ofh9rj8779+sKUPmRtp8pv8NsQsVXWH90ZiRl5RAi5NtGe4ztp05f98T9C8K8de3c40uNRmJ3VE08agm6L9is/QbGV2KO/7nStYILiSqm0xfgv80KaFVTpm8rDLP+R2mGpW5giET4ePyMcq7JikSbxZLC1cqqr1fobxuWo8KqN5X8GN4V+TPA4944gzcQDPTynrndJlb9hTpoBTkfHAJnYLJAbI3NP/bsvWTqPpCnqHuEihAdJNTP7vACiSJOk24JwIDAQAB
"""
    /// RSA-1024 private key (PKCS#8 DER, base64) — расшифровка ответов.
    private static let privateKey = """
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDl/TtBd/zpLD8XohNE43D43tivCT1d8poBqlX7ZjZe0z+MJPY9ildJoMziU8EOxL14iCpcjPYCBW013XJKEuMRZF6Co9c20TZAxfEJTqtKXoZ/wmva3CO1M8sogvHygDMOrqVdkrRDIfONkqPFZcLKkhrQaQUshrTFN7ljEgeD4FHK/FeHRcawq7oZZ3ekjEKToFNvcXmkeqI1Ie2JtQu52a9NXpWtGqFQoNdHAIsQGKQlQ3ZIQEp81XDip1D5DvMWPJq8dfIlmx0toi/8rZ0msNRkPHBEj3WtJCxW7zBLwOgGf2ehDwz9sNIAoWK50ixwfPRtjn8yuyDd6tj91wgFAgMBAAECggEADkN4x9QptspcNVqDaGvUp1KmzKA9kpSHsZ+/SmKp75KZZ9cpAGMSi8nxuv2nxQM1nwKO4gOKBFES11rfCjIGrB7175M6tzcdbsH383RSEkAvhj/oEYBCpKvMJzyLxdbmk7wIHHgLPvidksOr7YOko4yRJijFPeAy2OJeWIMXPTnvrg4m2CCCIKDMhRADkKM4LbbVsLJU6osg4/hdmuNNqOgoaQoL/YG+DriGC2g5s70j44+6emNBCvgUo7j/sBS/7jtXmXMhi+pwQ4ATpbmrBo2mDNOrzHwXXoF+6MQ2QfPw67T1D53cFlPvKncx/ZW0yeIBw63L8yuM/D5aEzsBoQKBgQD3vVkwaSzAC4hFSesE/j4RPgglz9I/WcbatpkD3pX1wx+UQZNLFMhZimmoQ/kQ1gpGxj9n1Uoe5nop60dYKT0BEcpA1wlhh9HJltq4cAQfCojtzU2YDhvJqA3uAx8TFEFRD/3KqPsMI07/e0Pg7+hMhblNRoL29aLYkP5XnuiSEQKBgQDtqF55g9u549gWDylE2bbaU1uP0G75fR5STj28dhAXrr9QOVWifH/IU+TQmkTpbY5HKA35V4x8oljokKuPDlYF2834+fFF8gdq9cUIZP5ZJ9wnz7sgYgtAyGjyglnL5MGCxGDgO1Gm9mioE2dd5seOYM9Tx+9OnCtzjV37rmmitQKBgQCpB4UR9cC1q2intd5ngryAcS2H9vrBhJSb55gRPs5cZ2xlcDR6NszX4wth5jbKmO9cCKl8Q9eVq7VQYppD+acI0sWHZfCdndiyTX4f9zWopDx22+wEQiQNe989NN3/24MRNvL3UkIvruuYftb6Y1XA2EBtDB4RN9mLH6qZx+9wsQKBgEopZ0neJtwMSKshkgxFMDVTG9h1/5tlOugOOF+uK/ln85VyPtHUrf9yho2+BlEdee+khS/Q7SsbckkolBCxNZDgdZcDUBI2o6/x/8lN0r05ng7iWQ+S6NYPdAhxOtpQiT5oT57JhAJpFGGWpIP99znr5ebMFlZej4SgkbpvQ9GdAoGAfQ7Joz29e8C1c0mnF6QUSf4XcIx/rP0gtFmepSOpOTF8i+w4OAo3+iko+j3tcBHH1XoZwV7ga6oTO+NizsjJoiKzulS9RoPwU268dXPq8C4ZZ7YaK8JemfiEuLI7XqKrNjogvHrD0xkuuzMK3W7Fz7vzJNMTkSiCfqIkOx84tO4=
"""

    // MARK: - MD5 / подписи integrity

    /// MD5 строки (UTF-8) → hex (Kotlin `md5Hex`).
    static func md5Hex(_ value: String) -> String {
        let data = Insecure.MD5.hash(data: Data(value.utf8))
        return data.map { String(format: "%02x", $0) }.joined()
    }

    /// Подпись integrity getSnConfig: sort-canon
    /// `deviceSn=..&randomStr=..&timestamp=..&key=<APP_SECRET>` → MD5 hex (uppercase).
    static func integritySign(deviceSn: String, randomStr: String, timestamp: String) -> String {
        let canonical = "deviceSn=\(deviceSn)&randomStr=\(randomStr)&timestamp=\(timestamp)"
        return md5Hex("\(canonical)&key=\(appSecret)").uppercased()
    }

    /// Тело запроса getSnConfig (Kotlin `signedSnConfigBody`):
    /// `{"body": {"deviceSn": ...}, "integrityData": {randomStr, timestamp, sign}}`.
    static func signedSnConfigBody(deviceSn: String, randomStr: String, timestamp: String) -> String {
        let object: [String: Any] = [
            "body": ["deviceSn": deviceSn],
            "integrityData": [
                "randomStr": randomStr,
                "timestamp": timestamp,
                "sign": integritySign(deviceSn: deviceSn, randomStr: randomStr, timestamp: timestamp),
            ],
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: object),
              let body = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return body
    }

    /// Decoding provisioned-материала: hex(32) или base64; принимается ровно 16B
    /// (Kotlin `decodeMaterial`).
    static func decodeMaterial(_ encoded: String) -> Data? {
        let trimmed = encoded.trimmingCharacters(in: .whitespacesAndNewlines)
        let data: Data
        if trimmed.count == 32, trimmed.allSatisfy({ $0.isHexDigit }) {
            var bytes = Data(capacity: 16)
            var index = trimmed.startIndex
            while index < trimmed.endIndex {
                let next = trimmed.index(index, offsetBy: 2)
                guard let byte = UInt8(trimmed[index..<next], radix: 16) else { return nil }
                bytes.append(byte)
                index = next
            }
            data = bytes
        } else {
            guard let decoded = Data(base64Encoded: trimmed) else { return nil }
            data = decoded
        }
        return data.count == 16 ? data : nil
    }

    // MARK: - Envelope (RSA-1024 PKCS#1 v1.5, chunked)

    /// Шифрование JSON-тела запроса: `{"encryptData": base64(RSA-1024-PKCS1(по 117B))}`
    /// (Kotlin `encryptEnvelope`). chunk = k-11 = 117 байт.
    static func encryptEnvelope(_ plainJson: String) -> Result<String, Error> {
        guard let data = plainJson.data(using: .utf8) else {
            return .failure(CnCloudError.encryption)
        }
        let key = publicSecKey
        guard let key else {
            return .failure(CnCloudError.encryption)
        }
        let maxBlock = 117 // 128 - 11 (PKCS#1 v1.5)
        var output = Data()
        var encError: Unmanaged<CFError>?
        var offset = data.startIndex
        while offset < data.endIndex {
            let end = data.index(offset, offsetBy: maxBlock)
            let chunk = data[offset..<end]
            guard let encryptedData = SecKeyCreateEncryptedData(key, rsaPkcs1, chunk as CFData, &encError) as Data? else {
                return .failure(CnCloudError.encryption)
            }
            output.append(encryptedData)
            offset = end
        }
        let json = try? JSONSerialization.data(withJSONObject: ["encryptData": output.base64EncodedString()])
        guard let json, let body = String(data: json, encoding: .utf8) else {
            return .failure(CnCloudError.encryption)
        }
        return .success(body)
    }

    /// Расшифровка `encryptData` ответа (Kotlin `decryptEnvelope`):
    /// по 128B блокав PKCS#1 v1.5 → plaintext JSON.
    static func decryptEnvelope(_ response: String) -> String? {
        guard let outer = response.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: outer) as? [String: Any],
              let encrypted = json["encryptData"] as? String,
              !encrypted.isEmpty else {
            return response.count == 0 ? nil : response
        }
        guard let key = privateSecKey,
              let input = Data(base64Encoded: encrypted) else { return nil }
        let blockSize = 128
        guard input.count % blockSize == 0 else { return nil }
        var output = Data()
        var offset = 0
        while offset < input.count {
            let chunk = input.subdata(in: offset..<min(offset + blockSize, input.count))
            var cfError: Unmanaged<CFError>?
            guard let decryptedData = SecKeyCreateDecryptedData(key, rsaPkcs1, chunk as CFData, &cfError) as Data? else {
                return nil
            }
            output.append(decryptedData)
            offset += blockSize
        }
        return String(data: output, encoding: .utf8)
    }

    // MARK: - SecKey

    /// RSA-PKCS1 v1.5 (SEC1) — Swift-импорт константы Security.framework:
    /// `SecKeyAlgorithm.rsaEncryptionPKCS1` (C: kSecKeyAlgorithmRSAEncryptionPKCS1).
    private static let rsaPkcs1: SecKeyAlgorithm = .rsaEncryptionPKCS1

    private static var publicSecKey: SecKey? = makeSecKey(publicKey, isPublic: true)
    private static var privateSecKey: SecKey? = makeSecKey(privateKey, isPublic: false)

    private static func makeSecKey(_ base64: String, isPublic: Bool) -> SecKey? {
        guard let der = Data(base64Encoded: base64) else { return nil }
        let attributes: [String: Any] = [
            String(kSecAttrKeyType): String(kSecAttrKeyTypeRSA),
            String(kSecAttrIsPermanent): false,
        ]
        return SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil)
    }
}

/// Ошибка CN-облака (без PII/секретов в message).
enum CnCloudError: LocalizedError {
    case encryption
    case invalidResponse
    case network(String)

    var errorDescription: String? {
        switch self {
        case .encryption: return "CN-облак: крипто-ошибка"
        case .invalidResponse: return "CN-облак: невалидный ответ"
        case .network(let message): return "CN-облак: \(message)"
        }
    }
}

/// Provisioned-материал сенсора (F001 secret + IV), полученный от CN-облака
/// (getSnConfig) вместо SN-деривации. Порт `AiDexProvisionedKeys`.
struct AidexPairingMaterial {
    let secret: Data  // 16B — F001 challenge
    let iv: Data      // 16B — IV

    /// Magic-префикс для будущей file-backup (Application Support) —
    /// `AiDexPairKeyBackup` (Kotlin, magic `JUGGLUCONG_AIDEX_PAIR_KEY`, version 1)
    /// при порте vault'а.
    static let backupMagic = "JUGGLUCONG_AIDEX_PAIR_KEY"
    static let backupVersion = 1

    init(secret: Data, iv: Data) {
        self.secret = secret
        self.iv = iv
    }
}
