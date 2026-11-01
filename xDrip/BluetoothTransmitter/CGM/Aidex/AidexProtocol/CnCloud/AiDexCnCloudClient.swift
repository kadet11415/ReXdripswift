import Foundation

/// Клиент CN-облака AiDEX (china.pancares.com): аккаунт + provisioned-материал
/// сенсора. Порт 1:1 из JugglucoNG `AiDexCnCloudClient` (Kotlin).
///
/// Каждый JSON-запрос/ответ — envelope из `AiDexCnProtocol` (RSA-1024 PKCS1 +
/// `{"encryptData": base64}`). Креденшелы, токены и полученный материал
/// deliberately не логируются.
///
/// Kotlin-объект synchronous; iOS-порт — async (URLSession) с completion'ами,
/// остальной протокол (заголовки, retry-политики, нормализация) — 1:1.
final class AiDexCnCloudClient {

    /// Результат CN-запроса (Kotlin `AiDexCnResult`).
    struct Result {
        let value: [String: Any]?
        let error: String
        let code: Int?

        init(value: [String: Any]? = nil, error: String = "", code: Int? = nil) {
            self.value = value
            self.error = error
            self.code = code
        }

        var isSuccess: Bool { value != nil && error.isEmpty }
    }

    // Endpoints и таймаут — 1:1 из `AiDexCnCloudClient`.
    private static let baseUrl = "https://china.pancares.com"
    private static let sendPhoneCode = "/backend/aidex-x/user/sendRegisterPhoneVerificationCode"
    private static let loginWithCode = "/backend/aidex-x/user/loginOrRegisterByVerificationCodeWithPhone"
    private static let loginWithPassword = "/backend/aidex-x/user/loginByPassword"
    private static let getSnConfig = "/backend/aidex-x/cgmDevice/getSnConfig"
    private static let timeoutMs = 20_000

    /// getSnConfig гейтится по mainland-China source IP; сервер честается
    /// `X-Forwarded-For`. Фиксированный IP быстро rate-limitится (все
    /// инсталы делят один), поэтому каждый запрос берёт свежий случайный
    /// адрес внутри давно выданных CN-выделений.
    /// (base, prefix) — большие многолетние CN-телеком/Baidu-выделения.
    private static let cnRoutingBlocks: [(base: UInt32, prefix: Int)] = [
        (cnIP("36.96.0.0"), 11), (cnIP("39.128.0.0"), 10), (cnIP("58.14.0.0"), 15), (cnIP("111.0.0.0"), 10),
        (cnIP("112.0.0.0"), 10), (cnIP("114.80.0.0"), 12), (cnIP("116.192.0.0"), 10), (cnIP("120.192.0.0"), 10),
        (cnIP("124.64.0.0"), 11), (cnIP("180.76.0.0"), 16), (cnIP("182.80.0.0"), 12), (cnIP("202.96.0.0"), 11),
        (cnIP("218.0.0.0"), 11), (cnIP("220.160.0.0"), 11), (cnIP("221.192.0.0"), 11), (cnIP("222.16.0.0"), 11),
    ]

    /// Сколько попыток getSnConfig (Kotlin `SN_CONFIG_ATTEMPTS = 4`).
    private static let snConfigAttempts = 4

    private static func cnIP(_ s: String) -> UInt32 {
        var value: UInt32 = 0
        for part in s.split(separator: ".") {
            value = (value << 8) | (UInt32(part) ?? 0)
        }
        return value
    }

    /// Случайный routable-хост внутри случайного CN-блока
    /// (skip network/broadcast-адресов). Kotlin: `host = 1 + Random.nextInt(
    /// (1 shl (32 - prefix)) - 2)` — диапазон [1, maxHost-2].
    static func randomCnRoutingIp() -> String {
        guard let block = cnRoutingBlocks.randomElement() else { return "0.0.0.0" }
        let maxHost = 1 << (32 - block.prefix)
        let host = 1 + Int(Int32.random(in: 0..<Int32(maxHost - 2)))
        let ip = block.base &+ (UInt32)(host)
        return "\(ip >> 24 & 0xFF).\(ip >> 16 & 0xFF).\(ip >> 8 & 0xFF).\(ip & 0xFF)"
    }

    /// Нормализация mainland-China номера (Kotlin `normalizeCnPhone`).
    static func normalizeCnPhone(raw: String) -> String? {
        var digits = raw.filter(\.isNumber)
        if digits.hasPrefix("0086"), digits.count == 15 { digits.removeFirst(4) }
        if digits.hasPrefix("86"), digits.count == 13 { digits.removeFirst(2) }
        guard digits.count == 11, digits.first == "1" else { return nil }
        guard let c2 = digits.dropFirst().first, "3456789".contains(c2) else { return nil }
        return digits
    }

    /// Запрос SMS-кода логина (registration-код; vendor не использует
    /// отдельный login-code endpoint — он отвечает biz 500).
    func requestLoginCode(phone: String, completion: @escaping (Result) -> Void) {
        guard let normalized = Self.normalizeCnPhone(raw: phone) else {
            completion(Result(error: "Invalid mainland China phone number"))
            return
        }
        postJson(AiDexCnCloudClient.sendPhoneCode, json: ["phone": normalized], token: "", useCnRouting: false, completion: { r in
            if r.isSuccess {
                completion(Result(error: "", code: r.code))
            } else {
                completion(Result(error: r.error, code: r.code))
            }
        })
    }

    /// Логин по SMS-коду → session (Kotlin `loginWithCode`).
    func loginWithCode(phone: String, code: String, completion: @escaping (Result) -> Void) {
        guard let normalized = Self.normalizeCnPhone(raw: phone) else {
            completion(Result(error: "Invalid mainland China phone number"))
            return
        }
        let trimmed = code.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            completion(Result(error: "Verification code is required"))
            return
        }
        login(AiDexCnCloudClient.loginWithCode, json: ["phone": normalized, "code": trimmed], completion: completion)
    }

    /// Логин по паролю (Kotlin `loginWithPassword`; пароль — MD5 hex).
    func loginWithPassword(phone: String, password: String, completion: @escaping (Result) -> Void) {
        guard let normalized = Self.normalizeCnPhone(raw: phone) else {
            completion(Result(error: "Invalid mainland China phone number"))
            return
        }
        if password.isEmpty {
            completion(Result(error: "Password is required"))
            return
        }
        login(AiDexCnCloudClient.loginWithPassword, json: [
            "userName": normalized,
            "password": AiDexCnProtocol.md5Hex(password),
        ], completion: completion)
    }

    /// Provisioned-материал сенсора (Kotlin `getProvisionedKeys`):
    /// secret (`publicKey`-поле) + iv (`communicationKey`-поле), ровно 16B
    /// (`decodeMaterial`). Каждый attempt — свежий случайный CN IP через
    /// `X-Forwarded-For`; повторы только transient-коды 500/100010
    /// («请求过于频繁» / China-availability), прочие ошибки — стоп сразу.
    func getProvisionedKeys(serial: String, token: String, completion: @escaping (Result) -> Void) {
        let bareSerial = SerialCrypto.stripPrefix(serial)
        if bareSerial.isEmpty {
            completion(Result(error: "Invalid sensor serial"))
            return
        }
        if token.isEmpty {
            completion(Result(error: "Sign in is required"))
            return
        }
        attemptGetSnConfig(bareSerial: bareSerial, token: token, attempt: 0, completion: completion)
    }

    // MARK: - private

    private func attemptGetSnConfig(bareSerial: String, token: String, attempt: Int, completion: @escaping (Result) -> Void) {
        guard attempt < AiDexCnCloudClient.snConfigAttempts else {
            completion(Result(error: "getSnConfig failed", code: nil))
            return
        }
        let random = {
            var bytes = [UInt8](repeating: 0, count: 8)
            _ = SecRandomCopyBytes(nil, 8, &bytes)
            return bytes.map { String(format: "%02x", $0) }.joined()
        }()
        let timestamp = Int64(Date().timeIntervalSince1970 * 1000).description
        let body = AiDexCnProtocol.signedSnConfigBody(deviceSn: bareSerial, randomStr: random, timestamp: timestamp)
        postJson(AiDexCnCloudClient.getSnConfig, body: body, token: token, useCnRouting: true, completion: { [weak self] r in
            guard let data = r.value else {
                // Повтор (retry) только для transient-кодов 500/100010.
                if r.code == 500 || r.code == 100010 {
                    self?.attemptGetSnConfig(bareSerial: bareSerial, token: token, attempt: attempt + 1, completion: completion)
                } else {
                    completion(Result(error: r.error, code: r.code))
                }
                return
            }
            let responseSerial = (data["deviceSn"] as? String) ?? ""
            if !responseSerial.isEmpty,
               SerialCrypto.stripPrefix(responseSerial).lowercased() != bareSerial.lowercased() {
                completion(Result(error: "Server returned pairing material for another sensor"))
                return
            }
            guard let secret = AiDexCnProtocol.decodeMaterial((data["publicKey"] as? String) ?? ""),
                  let iv = AiDexCnProtocol.decodeMaterial((data["communicationKey"] as? String) ?? "") else {
                completion(Result(error: "Server returned invalid pairing material", code: r.code))
                return
            }
            let material = AidexPairingMaterial(secret: secret, iv: iv)
            completion(Result(value: ["material": material], error: "", code: r.code))
        })
    }

    private func login(_ path: String, json: [String: Any], completion: @escaping (Result) -> Void) {
        guard let body = jsonToOrderedString(json) else {
            completion(Result(error: "Invalid request body"))
            return
        }
        postJson(path, body: body, token: "", useCnRouting: false, completion: { r in
            guard let data = r.value, let tokenValue = data["token"] as? String, !tokenValue.isEmpty else {
                completion(Result(error: r.error.isEmpty ? "The server did not return a session" : r.error, code: r.code))
                return
            }
            completion(Result(value: ["token": tokenValue], error: "", code: r.code))
        })
    }

    /// POST envelope (Kotlin `post`): шифруем тело, расшифровываем ответ,
    /// валидим http 2xx + business `code == 200`.
    private func postJson(_ path: String, body: String, token: String, useCnRouting: Bool,
                          completion: @escaping (Result) -> Void) {
        guard let url = URL(string: AiDexCnCloudClient.baseUrl + path) else {
            completion(Result(error: "Invalid URL"))
            return
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = Double(AiDexCnCloudClient.timeoutMs) / 1000
        request.setValue("application/json;charset=UTF-8", forHTTPHeaderField: "Content-Type")
        request.setValue("enabled", forHTTPHeaderField: "encryption")
        request.setValue("v2", forHTTPHeaderField: "X-Key-version")
        request.setValue(Locale.current.identifier, forHTTPHeaderField: "Accept-Language")
        request.setValue(userAgentString(), forHTTPHeaderField: "User-Agent")
        // X-Forwarded-For — только для getSnConfig (China-гейт);
        // account-запросы — как у официального клиента, по реальному IP.
        if useCnRouting {
            request.setValue(Self.randomCnRoutingIp(), forHTTPHeaderField: "X-Forwarded-For")
        }
        if !token.isEmpty {
            request.setValue(token, forHTTPHeaderField: "x-token")
        }
        request.httpBody = body.data(using: .utf8)

        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data else {
                let message = (error as? URLError)?.localizedDescription ?? "unknown"
                completion(Result(error: "Network error: \(message)"))
                return
            }
            let httpCode = (response as? HTTPURLResponse)?.statusCode ?? 0
            let text = String(data: data, encoding: .utf8) ?? ""
            let decoded = AiDexCnProtocol.decryptEnvelope(text) ?? text
            guard let jsonData = decoded.data(using: .utf8),
                  let root = try? JSONSerialization.jsonObject(with: jsonData, options: .fragmentsAllowed),
                  let dict = root as? [String: Any] else {
                completion(Result(error: "Invalid server response"))
                return
            }
            let businessCode = (dict["code"] as? NSNumber)?.intValue ?? Int.min
            let ok = (200...299).contains(httpCode) && businessCode == 200
            if ok {
                let dataDict = dict["data"] as? [String: Any] ?? [:]
                completion(Result(value: dataDict, error: "", code: businessCode))
            } else {
                let message = (dict["msg"] as? String) ?? (dict["message"] as? String) ?? ""
                let text = "http=\(httpCode) biz=\(businessCode) \(message.prefix(120))".trimmingCharacters(in: .whitespaces)
                completion(Result(error: text, code: businessCode))
            }
        }
        task.resume()
    }

    /// POST, где тело — JSON-объект: сериализуем в строку перед envelope'ом.
    private func postJson(_ path: String, json: [String: Any], token: String, useCnRouting: Bool,
                          completion: @escaping (Result) -> Void) {
        guard let body = jsonToOrderedString(json) else {
            completion(Result(error: "Invalid request body"))
            return
        }
        postJson(path, body: body, token: token, useCnRouting: useCnRouting, completion: completion)
    }

    private func jsonToOrderedString(_ object: [String: Any]) -> String? {
        guard let data = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// User-Agent в форме официального клиента
    /// `android<SDK>-<BRAND>-<MODEL>,com.microtech.aidexx,1.15.1` — iOS-эталон.
    private func userAgentString() -> String {
        #if canImport(UIKit)
        let osMajor = UIDevice.current.systemVersion
        let model = UIDevice.current.model
        return "android\(osMajor)-Apple-\(model),com.microtech.aidexx,1.15.1"
        #else
        return "android17-Apple-iPhone,com.microtech.aidexx,1.15.1"
        #endif
    }
}
