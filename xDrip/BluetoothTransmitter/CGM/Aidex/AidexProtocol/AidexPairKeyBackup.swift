import Foundation
import CryptoKit

/// Потоно-портируемое, версионируемое представление стабильного
/// AiDex PAIR-кредентиала. 1:1 из JugglucoNG `AiDexPairKeyBackup`.
///
/// Формат текстовой записи (export-стринга) — ровно:
/// ```
/// JUGGLUCONG_AIDEX_PAIR_KEY
/// version=1
/// sensor=<BARE_SERIAL upper>
/// pair_key=<HEX upper, 32 hex-символа>
/// sha256=<lowercase hex SHA-256("MAGIC\nVERSION\nsensor\nkeyHex")>
/// ```
enum AiDexPairKeyBackup {
    static let magic = "JUGGLUCONG_AIDEX_PAIR_KEY"
    static let version = "1"
    static let pairKeyBytes = 16

    struct Record {
        let bareSerial: String
        let pairKey: Data
    }

    /// Канонический bare-serial: stripPrefix + trim + upper (Kotlin
    /// `canonicalBareSerial`).
    static func canonicalBareSerial(_ serial: String) -> String {
        SerialCrypto.stripPrefix(serial).trimmingCharacters(in: .whitespaces).uppercased()
    }

    static func encode(serial: String, pairKey: Data) -> String? {
        guard pairKey.count == pairKeyBytes else { return nil }
        let bareSerial = canonicalBareSerial(serial)
        guard !bareSerial.isEmpty else { return nil }
        let keyHex = pairKey.uppercasedHex
        return """
        \(magic)
        version=\(version)
        sensor=\(bareSerial)
        pair_key=\(keyHex)
        sha256=\(checksum(bareSerial: bareSerial, keyHex: keyHex))
        """
    }

    static func decode(_ payload: String) -> Record? {
        let lines = payload
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard let first = lines.first, first == magic else { return nil }
        var fields: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let sep = line.firstIndex(of: "=") else { continue }
            guard line.distance(from: line.startIndex, to: sep) >= 1 else { continue }
            let key = String(line[..<sep]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: sep)...]).trimmingCharacters(in: .whitespaces)
            fields[key] = value
        }
        guard fields["version"] == version else { return nil }
        let bareSerial = canonicalBareSerial(fields["sensor"] ?? "")
        guard !bareSerial.isEmpty else { return nil }
        let keyHex = (fields["pair_key"] ?? "").uppercased()
        // hex-decode ровно 16 байт (Kotlin `hexToBytes`): длина 32, парные hex-символы.
        guard keyHex.count == pairKeyBytes * 2 else { return nil }
        var key = Data(capacity: pairKeyBytes)
        for i in 0..<pairKeyBytes {
            let pair = keyHex[keyHex.index(keyHex.startIndex, offsetBy: i * 2)..<keyHex.index(keyHex.startIndex, offsetBy: i * 2 + 2)]
            guard let byte = UInt8(pair, radix: 16) else { return nil }
            key.append(byte)
        }
        guard let expected = checksumData(bareSerial: bareSerial, keyHex: keyHex),
              let actual = fields["sha256"]?.lowercased() else { return nil }
        guard expected == actual else { return nil }
        guard bareSerial == canonicalBareSerial(bareSerial) else { return nil }
        return Record(bareSerial: bareSerial, pairKey: key)
    }

    /// `sha256("<magic>\n<version>\n<bareSerial>\n<keyHex>")` lowercase-hex
    /// (Kotlin `checksum`, MessageDigest SHA-256).
    static func checksum(bareSerial: String, keyHex: String) -> String {
        return checksumData(bareSerial: bareSerial, keyHex: keyHex) ?? ""
    }

    private static func checksumData(bareSerial: String, keyHex: String) -> String? {
        let input = "\(magic)\n\(version)\n\(bareSerial)\n\(keyHex)"
        let digest = SHA256.hash(data: Data(input.utf8))
        return Data(digest).map { String(format: "%02x", $0) }.joined()
    }
}

extension Data {
    var uppercasedHex: String { map { String(format: "%02X", $0) }.joined() }
    var lowercasedHex: String { map { String(format: "%02x", $0) }.joined() }
}
