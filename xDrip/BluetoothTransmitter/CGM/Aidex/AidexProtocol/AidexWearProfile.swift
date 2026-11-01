// AidexWearProfile.swift — Rated wear from the official default-parameter catalog,
// resolved against startup 0x10. 1:1 Kotlin `AiDexWearProfile`.
//
// Каждый официальный параметрический файл хранит рейтинг как little-endian
// uint32 секунд на байте 4 `settingContent`. Значение одинаково для всех
// fw модели: GX-01S — 15 дней, GX-02S — 10, GX-03S — 8, GXXXS — 7/14/16.
// Байт сенсора (0x10) всегда побеждает; рейтинг подставляется, пока байт не
// читался (display only — cutoff/expiry остаются на байте 0x10).

import Foundation

enum AidexWearProfile {

    // Рейтинг по модели из snapshot официального каталога (69 entries,
    // AiDexOfficialDpCatalogSnapshot, 1:1: один distinct-день на settingType).
    private static let ratedDaysBySettingType: [String: Int] = [
        "1034_GX01S": 15,
        "1034_GX02S": 10,
        "1034_GX03S": 8,
        "1034_GXXXS_7": 7,
        "1034_GXXXS_14": 14,
        "1034_GXXXS_16": 16,
    ]

    private static let secondsPerDay = 86_400
    private static let wearSecOffset = 4

    /// Дней из поля settingContent; nil, если поле не целое число дней.
    /// (Kotlin `catalogWearDays`: bytes 4..7 LE → seconds; 86400-integral check.)
    static func catalogWearDays(settingContent: String) -> Int? {
        let hex = settingContent.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hex.count >= (wearSecOffset + 4) * 2, hex.count % 2 == 0 else { return nil }
        let chars = Array(hex)
        guard chars.count == hex.count else { return nil }
        var seconds: UInt32 = 0
        for index in 0..<4 {
            let pair = String(chars[(wearSecOffset + index) * 2 ..< (wearSecOffset + index) * 2 + 2])
            guard let byte = UInt8(pair, radix: 16) else { return nil }
            seconds |= UInt32(byte) << (8 * index)
        }
        guard seconds > 0, seconds % UInt32(secondsPerDay) == 0 else { return nil }
        return Int(seconds) / secondsPerDay
    }

    /// Рейтинг по имени модели (DIS / startup 0x10: «GX-02S», «1034_GX02S», …).
    /// nil, если модель неизвестна или файлы каталога не согласованы.
    /// (Kotlin `ratedDays(modelName)`.)
    static func ratedDays(_ modelName: String?) -> Int? {
        guard let settingType = normalizeCatalogModelName(modelName) else { return nil }
        return ratedDaysBySettingType[settingType]
    }

    /// (Kotlin `AiDexDefaultParamProvisioning.normalizeCatalogModelName` 1:1.)
    static func normalizeCatalogModelName(_ modelName: String?) -> String? {
        guard let name = modelName, !name.isEmpty else { return nil }
        let normalized = name.uppercased().filter { $0.isLetter || $0.isNumber }
        if normalized.contains("GX01S") { return "1034_GX01S" }
        if normalized.contains("GX02S") { return "1034_GX02S" }
        if normalized.contains("GX03S") { return "1034_GX03S" }
        if normalized.contains("GXXXS14") { return "1034_GXXXS_14" }
        if normalized.contains("GXXXS16") { return "1034_GXXXS_16" }
        if normalized.contains("GXXXS7") { return "1034_GXXXS_7" }
        return nil
    }

    // (Kotlin `AiDexWearProfile.resolve` — оба overload'а.)

    /// Байт сенсора побеждает; рейтинг — только пока байт не читался.
    static func resolve(sensorDays: Int?, modelDays: Int?) -> Int? {
        if let s = sensorDays, s > 0 { return s }
        if let m = modelDays, m > 0 { return m }
        return nil
    }

    /// Remembered-байт прошлых соединений рангует выше рейтинга, ниже свежего.
    static func resolve(sensorDays: Int?, rememberedSensorDays: Int?, modelDays: Int?) -> Int? {
        let fresh = (sensorDays ?? 0) > 0 ? sensorDays : nil
        return resolve(sensorDays: fresh ?? rememberedSensorDays, modelDays: modelDays)
    }
}
