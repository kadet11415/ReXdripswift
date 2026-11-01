import Foundation

// MARK: - Frame Parser

/// Парсинг F003 фреймов, F002 ответов, history и calibration данных.
enum AidexParser {

    // MARK: - F003 Classification

    enum FrameType { case data, status, calibration, unknown }

    static func classifyFrame(_ data: Data) -> FrameType {
        switch data.count {
        case AidexFrame.dataFrameLength:                    return .data
        case AidexFrame.statusFrameLength:                  return .status
        case AidexFrame.calibrationNotificationLength:      return .calibration
        default:                                            return .unknown
        }
    }

    // MARK: - 17-byte Data Frame

    /// Парсинг 17-байтового дешифрованного F003-фрейма.
    ///
    /// Layout:
    /// - `byte[0]` — opcode (scaling / тип фрейма);
    /// - `bytes[1..3]` — неопознанные (не-ноль, меняются от кадра к кадру);
    /// - `bytes[4..5]` — `timeOffsetMinutes` (u16 LE) — минуты с момента старта
    ///   сенсора — тот же u16, что и в history 0x23/0x24/0x27 и калиб-пейлодах;
    /// - `bytes[6..7]` — `glucosePacked` (u16 LE), `glucose = packed & 0x03FF` (10-bit);
    /// - `bytes[8..9]` — `i1` (u16 LE / 100), `bytes[10..11]` — `i2` (u16 LE / 100) — raw-каналы;
    /// - `bytes[15..16]` — CRC-16/CCITT-FALSE (u16 LE).
    ///
    /// Раньше поле времени читалось как u32-секунды на `bytes[1..4]` — это давало
    /// десятки миллионов "минут" на каждой прошивке, из-за чего драйвер тащил
    /// "garbage timing bytes" workaround. Поле — это u16 LE минут на `bytes[4..5]`.
    static func parseDataFrame(_ data: Data) -> GlucoseFrame? {
        guard data.count == AidexFrame.dataFrameLength else { return nil }

        let opcode = data[0]
        let timeOffsetMinutes = Int(data.subdata(in: 4..<6).toU16LE())
        let glucosePacked = Int(data.subdata(in: 6..<8).toU16LE())
        let rawGlucose = glucosePacked & AidexFrame.glucoseMask
        let i1Raw = Int(data.subdata(in: 8..<10).toU16LE())
        let i2Raw = Int(data.subdata(in: 10..<12).toU16LE())
        let crc16 = data.subdata(in: 15..<17).toU16LE()

        let i1 = Float(i1Raw) / 100.0
        let i2 = Float(i2Raw) / 100.0
        // Неизвестный opcode — не glucose frame; парсится raw-значение без scaling,
        // а решение o-приём/отбраковка принимает обработчик (см. scalingFactor(for:)).
        let scale = scalingFactor(for: opcode) ?? 1.0
        let glucoseMgDl = Float(rawGlucose) * scale

        let isSentinel = rawGlucose == AidexFrame.sentinelGlucose
        let isInRange = rawGlucose >= AidexFrame.minValidGlucose
                     && rawGlucose <= AidexFrame.maxValidGlucose
        let isValid = !isSentinel && isInRange

        return GlucoseFrame(
            opcode: opcode,
            timeOffsetMinutes: timeOffsetMinutes,
            glucoseMgDl: glucoseMgDl,
            rawGlucosePacked: rawGlucose,
            i1: i1,
            i2: i2,
            crc16: crc16,
            isValid: isValid
        )
    }

    /// Проверка CRC-16 в F003 фрейме (байты 0..14 payload, 15..16 CRC).
    static func validateFrameCRC(_ decrypted: Data) -> Bool {
        guard decrypted.count >= AidexFrame.dataFrameLength else { return false }
        let payload = decrypted.prefix(15)
        let frameCRC = decrypted.subdata(in: 15..<17).toU16LE()
        return CRC16.checksum(payload) == frameCRC
    }

    // MARK: - Broadcast Sample (0x11 response / advertising record)

    /// Образец broadcast-глюкозы (GATT-ответ 0x11 или запись advertising в
    /// broadcast-only режиме). Минимум 7 байт:
    /// - `[0..3]` — offset u32LE (валидация `0 < off <= 30д*1440`); при невалидном —
    ///   fallback u16LE `[0..1]`;
    /// - `[4]` — trend (1B, без расшифровки — только значение);
    /// - `glucose` — 10-bit пакетирование: `byte[5] | ((byte[6] & 0x03) << 8)`;
    ///   fallback — простой `byte[5]`;
    /// - принимается первое значение (packed, потом fallback) в диапазоне 20..500;
    ///   вне диапазона — reject.
    struct BroadcastSample {
        let offsetMinutes: Int
        let trend: Int
        let glucoseMgDl: Int
    }

    static func parseBroadcastSamplePayload(_ payload: Data) -> BroadcastSample? {
        guard payload.count >= 7 else { return nil }

        let offsetCandidate = Int(payload.subdata(in: 0..<4).toU32LE(at: 0))
        let maxOffsetMinutes = 30 * 24 * 60
        let offsetMinutes: Int
        if offsetCandidate > 0, offsetCandidate <= maxOffsetMinutes {
            offsetMinutes = offsetCandidate
        } else {
            offsetMinutes = Int(payload.subdata(in: 0..<2).toU16LE(at: 0))
        }
        guard offsetMinutes > 0, offsetMinutes <= maxOffsetMinutes else { return nil }

        let trend = Int(payload[4])
        let packed = Int(payload[5]) | ((Int(payload[6]) & 0x03) << 8)
        let fallback = Int(payload[5])

        let glucoseMgDl: Int
        if (AidexFrame.minValidGlucose...AidexFrame.maxValidGlucose).contains(packed) {
            glucoseMgDl = packed
        } else if (AidexFrame.minValidGlucose...AidexFrame.maxValidGlucose).contains(fallback) {
            glucoseMgDl = fallback
        } else {
            return nil
        }

        return BroadcastSample(offsetMinutes: offsetMinutes, trend: trend, glucoseMgDl: glucoseMgDl)
    }

    // MARK: - History Parsing

    /// GET_HISTORIES_RAW (0x23): калиброванная глюкоза, 2-байтные записи.
    static func parseHistoryResponse(_ data: Data) -> [CalibratedHistoryEntry] {
        guard data.count >= 4 else { return [] }

        let startOffset = Int(data.subdata(in: 0..<2).toU16LE())
        let body = data.subdata(in: 2..<data.count)
        let rowCount = body.count / 2

        return (0..<rowCount).map { i in
            let off = i * 2
            let b0 = Int(body[off])
            let b1 = Int(body[off + 1])
            let glucose = b0 | ((b1 & 0x03) << 8)
            return CalibratedHistoryEntry(
                timeOffsetMinutes: startOffset + i,
                glucoseMgDl: glucose,
                statusBit: (b1 & 0x04) != 0,
                isSentinel: glucose == AidexFrame.sentinelGlucose
            )
        }
    }

    /// GET_HISTORIES (0x24): сырые ADC данные, 5-байтные записи.
    static func parseBriefHistoryResponse(_ data: Data) -> [AdcHistoryEntry] {
        guard data.count >= 7 else { return [] }

        let startOffset = Int(data.subdata(in: 0..<2).toU16LE())
        let body = data.subdata(in: 2..<data.count)
        let rowCount = body.count / 5

        return (0..<rowCount).compactMap { i in
            let off = i * 5
            let i1Raw = Int(body.subdata(in: off..<off+2).toU16LE())
            let i2Raw = Int(body.subdata(in: off+2..<off+4).toU16LE())
            let vcRaw  = Int(body[off + 4])

            // Пропуск невалидных записей
            guard i1Raw != 0 || i2Raw != 0 || vcRaw != 0 else { return nil }

            let i1 = Float(i1Raw) / 100.0
            let i2 = Float(i2Raw) / 100.0
            let vc = Float(vcRaw) / 100.0

            return AdcHistoryEntry(
                timeOffsetMinutes: startOffset + i,
                i1: i1, i2: i2, vc: vc,
                rawValue: i1 * 10.0,
                sensorGlucose: i1 * 18.0182
            )
        }
    }

    // MARK: - GET_HISTORY_RANGE (0x22)

    /// Ответ GET_HISTORIES_RANGE (0x22) — полный фрейм
    /// `[op, ack, briefStart u16LE, rawStart u16LE, newestOffset u16LE]` (§4.4).
    static func parseHistoryRange(_ data: Data) -> HistoryRange? {
        guard data.count >= 8 else { return nil }
        return HistoryRange(
            briefStart: Int(data.subdata(in: 2..<4).toU16LE()),
            rawStart: Int(data.subdata(in: 4..<6).toU16LE()),
            newestOffset: Int(data.subdata(in: 6..<8).toU16LE())
        )
    }

    // MARK: - Calibration

    /// Ответ GET_CALIBRATION_RANGE (0x26) — полный фрейм:
    /// `[op, ack, startIdx u16LE, newestIdx u16LE]` (§4.4/§12).
    static func parseCalibrationRange(_ data: Data) -> CalibrationRange? {
        guard data.count >= 6 else { return nil }
        return CalibrationRange(
            startIndex: Int(data.subdata(in: 2..<4).toU16LE()),
            endIndex: Int(data.subdata(in: 4..<6).toU16LE())
        )
    }

    /// GET_CALIBRATION (0x27).
    static func parseCalibrationResponse(_ data: Data) -> [CalibrationRecord] {
        guard data.count >= 10 else { return [] }

        let startIndex = Int(data.subdata(in: 0..<2).toU16LE())
        guard startIndex <= 10000 else { return [] }

        let body = data.subdata(in: 2..<data.count)
        guard body.count % 8 == 0 else { return [] }

        let rowCount = body.count / 8
        return (0..<rowCount).map { i in
            let off = i * 8
            let timeOffset = Int(body.subdata(in: off..<off+2).toU16LE())
            let reference = Int(body.subdata(in: off+2..<off+4).toU16LE())
            let cfRaw = Int(body.subdata(in: off+4..<off+6).toU16LE())
            // offset — SIGNED (s16 LE) по §12/§4.4 (Kotlin `s16LE(data, off + 6)`):
            // отрицательные offset'ы кодируются 0xFFxx; u16LE читал их как
            // +655xx → /100 = +655 вместо −0.5x.
            let offsetRaw = Int(body.subdata(in: off+6..<off+8).toS16LE())
            return CalibrationRecord(
                index: startIndex + i,
                timeOffsetMinutes: timeOffset,
                referenceGlucoseMgDl: reference,
                calibrationFactor: Float(cfRaw) / 100.0,
                calibrationOffset: Float(offsetRaw) / 100.0
            )
        }
    }

    // MARK: - Startup Device Info (0x10)

    static func parseStartupDeviceInfoPayload(_ payload: Data) -> StartupDeviceInfo? {
        guard payload.count >= 16 else { return nil }
        guard payload.subdata(in: 0..<2).toU16LE(at: 0) == 0 else { return nil }
        return parseStartupDeviceInfoBody(payload)
    }

    /// Тело 0x10-ответа (Kotlin `parseStartupDeviceInfoBody`):
    /// `[status u16 [0..1] (здесь не проверяется) | fw_major[2] fw_minor[3] |
    ///  hw_major[4] hw_minor[5] | wear_days[6] | modelCode[7] | model ASCII 8..NUL]`.
    /// Используется для ACK-варианта, где status может быть non-zero
    /// (например: fw 1.7.1 Lumi GX-01S ответил 0x8000).
    static func parseStartupDeviceInfoBody(_ payload: Data) -> StartupDeviceInfo? {
        guard payload.count >= 16 else { return nil }

        let fwMajor = Int(payload[2])
        let fwMinor = Int(payload[3])
        let hwMajor = Int(payload[4])
        let hwMinor = Int(payload[5])
        let wearDays = Int(payload[6])
        let modelBytes = payload.subdata(in: 8..<payload.count)
        let modelName = String(bytes: modelBytes.prefix { $0 != 0 }, encoding: .ascii)?
            .trimmingCharacters(in: .whitespaces) ?? ""

        guard !modelName.isEmpty else { return nil }

        return StartupDeviceInfo(
            firmwareVersion: "\(fwMajor).\(fwMinor)",
            hardwareVersion: "\(hwMajor).\(hwMinor)",
            wearDays: wearDays,
            modelName: modelName
        )
    }

    /// 0x10-фрейм с опциональным CRC-trailer'ом.
    ///
    /// Frame-варианты (§12, Kotlin `parseStartupDeviceInfoFrame`):
    /// 1) payload = frame[1..payloadEnd) — стандартный;
    /// 2) body = frame[2..payloadEnd) как payload (status = body[0..2]);
    /// 3) ACK-вариант: `frame[1]==0x01`, body = frame[2..payloadEnd) — status
    ///    non-zero допустим (model code, напр. 0x8000); имя модели —
    ///    printable ASCII.
    ///
    /// CRC-16/CCITT-FALSE проверяется над всеми предыдущими байтами (LE):
    /// при валидном — срезается (payloadEnd = size-2).
    static func parseStartupDeviceInfoFrame(_ frame: Data, payloadEndExclusive: Int? = nil) -> StartupDeviceInfo? {
        let end = payloadEndExclusive ?? frame.count
        guard end > 1, end <= frame.count else { return nil }

        let response = frame.prefix(end)
        guard end >= 3, CRC16.validateResponse(Data(response)) else { return nil }
        let payloadEnd = end - 2

        // 1) payload от 1
        if let info = parseStartupDeviceInfoPayload(frame.subdata(in: 1..<payloadEnd)) {
            return info
        }
        // 2) body от 2 как payload
        guard payloadEnd > 2 else { return nil }
        if let info = parseStartupDeviceInfoPayload(frame.subdata(in: 2..<payloadEnd)) {
            return info
        }
        // 3) ACK-вариант: frame[1] == 0x01, body от 2 (status/model-code может быть non-zero)
        guard frame[1] == 0x01 else { return nil }
        if let info = parseStartupDeviceInfoBody(frame.subdata(in: 2..<payloadEnd)) {
            let printable = info.modelName.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value <= 0x7E }
            if printable { return info }
        }
        return nil
    }

    // MARK: - Session Start Time

    static func parseLocalStartTimePayload(_ payload: Data) -> LocalStartTime? {
        guard payload.count >= 7 else { return nil }

        let parsed = LocalStartTime(
            year: Int(payload.subdata(in: 0..<2).toU16LE()),
            month: Int(payload[2]),
            day: Int(payload[3]),
            hour: Int(payload[4]),
            minute: Int(payload[5]),
            second: Int(payload[6]),
            tzQuarters: payload.count >= 8 ? Int(Int8(bitPattern: payload[7])) : 0,
            dstQuarters: payload.count >= 9 ? Int(payload[8]) : 0
        )

        if parsed.isAllZeros { return parsed }

        let plausible = parsed.year >= 2020 && parsed.year <= 2040
            && parsed.month >= 1 && parsed.month <= 12
            && parsed.day >= 1 && parsed.day <= 31
            && parsed.hour >= 0 && parsed.hour <= 23
            && parsed.minute >= 0 && parsed.minute <= 59
            && parsed.second >= 0 && parsed.second <= 59

        return plausible ? parsed : nil
    }

    // MARK: - Default Param (0x31)

    static func parseDefaultParamChunk(_ payload: Data) -> DefaultParamChunk? {
        guard payload.count >= 5 else { return nil }

        let totalWords = Int(payload[1])
        let startIndex = Int(payload[2])
        let rawChunk = payload.subdata(in: 3..<payload.count)

        guard totalWords > 0, startIndex > 0, startIndex <= totalWords else { return nil }
        guard !rawChunk.isEmpty, rawChunk.count % 2 == 0 else { return nil }

        return DefaultParamChunk(
            leadByte: payload[0],
            totalWords: totalWords,
            startIndex: startIndex,
            rawChunk: rawChunk
        )
    }
}

// MARK: - Data Extensions

extension Data {
    func toU16LE(at offset: Int = 0) -> UInt16 {
        UInt16(self[offset]) | (UInt16(self[offset + 1]) << 8)
    }

    func toS16LE(at offset: Int = 0) -> Int16 {
        let u = toU16LE(at: offset)
        return Int16(bitPattern: u)
    }

    func toU32LE(at offset: Int = 0) -> UInt32 {
        var value: UInt32 = 0
        for i in 0..<4 {
            value |= UInt32(self[offset + i]) << (i * 8)
        }
        return value
    }
}

extension UInt32 {
    init(littleEndianData data: Data) {
        self = data.withUnsafeBytes { $0.load(as: UInt32.self) }
    }
}