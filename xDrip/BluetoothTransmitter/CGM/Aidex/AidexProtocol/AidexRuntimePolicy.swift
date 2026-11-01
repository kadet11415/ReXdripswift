import Foundation

/// §24: `AiDexRuntimePolicy` (Kotlin) — 1:1 чистые политики key-exchange.
///
/// Портировано ровно то, что читает Swift-драйвер:
/// `decidePairKeyStartAction`, `decideKeyExchangeFailureAction`,
/// `decideShortBondReadAction`, `shouldClearPersistedPairKey`,
/// `isClearStorageConfirmed`, `commandAccepted`.
/// (GATT-queue/MTU/bondState-функции Kotlin-объекта не портируются:
/// iOS bond-состояния нет, CCCD-ordering — в AidexSensorDelegates.)
enum AidexRuntimePolicy {

    /// Status-байт ACK F002-команды: AiDex отвечает `[opcode, status, crc16]`,
    /// `0x01` — успех (calibration 0x25, DELETE_BOND 0xF2, CLEAR_STORAGE 0xF3).
    /// `0x00` — отказ (единственный записанный случай — CLEAR_STORAGE 1.8.3).
    static let commandAccepted: UInt8 = 0x01

    /// Длина BOND-вектора (17 байт, F002 read).
    static let bondVectorLength = 17

    /// Макс. повторений одного key-exchange (saved или fresh) через чистое
    /// соединение (Kotlin `KEY_EXCHANGE_MAX_FAILURES`).
    static let keyExchangeMaxFailures = 3

    /// Delay (мс) перед повторным чтением BOND при коротком отказе —
    /// один re-read разрешён, вектор мог ещё не быть готовым.
    static let bondRereadDelayMs: Int = 400

    enum PairKeyStartAction {
        case useSavedKey
        case freshPair
    }

    enum KeyExchangeFailureAction {
        case retryCleanGatt
        /// Fresh pair после подтверждённого reset'а терпел неудачи:
        /// reset, видимо, не задел credential — вернёмся к хранимому ключу.
        case restoreSavedKey
        /// Хранящийся ключ исчерпал ретраи на bonded-ссылке:
        /// заменим его через F001.
        case replaceSavedKey
        /// Ни GATT, ни замены — ждём пользователя (broadcast-only fallback).
        case broadcastOnly
    }

    enum ShortBondReadAction {
        case accept
        case reread
        case failKeyExchange
    }

    /// Чем начиняется следующий key-exchange.
    ///
    /// Хранимый ключ используется, если он есть, bonded или не bonded: F002/F003
    /// принимают CCCD-записи по нешифрованному каналу — безопасность там
    /// app-слой AES с PAIR-ключом, а не SMP; F001 требует bond. Без хранимого
    /// ключа сенсор свежепается через F001.
    /// (Kotlin `AiDexRuntimePolicy.decidePairKeyStartAction` 1:1.)
    static func decidePairKeyStartAction(
        hasSavedPairKey: Bool,
        savedKeyExhausted: Bool = false,
        explicitPairRequested: Bool = false,
        bonded: Bool = false,
        pairKeyResetPending: Bool = false
    ) -> PairKeyStartAction {
        if !hasSavedPairKey { return .freshPair }
        // Сенсор подтвердил CLEAR_STORAGE: хранимый ключ мёртв — свежий pair.
        if pairKeyResetPending { return .freshPair }
        if savedKeyExhausted && (explicitPairRequested || bonded) { return .freshPair }
        return .useSavedKey
    }

    /// Key-exchange (saved- или fresh) не дал рабочую сессию.
    /// (Kotlin `decideKeyExchangeFailureAction` 1:1.)
    static func decideKeyExchangeFailureAction(
        consecutiveFailures: Int,
        maxFailures: Int,
        usedSavedKey: Bool = false,
        bonded: Bool = false,
        freshPairAfterReset: Bool = false
    ) -> KeyExchangeFailureAction {
        if consecutiveFailures < maxFailures { return .retryCleanGatt }
        if freshPairAfterReset { return .restoreSavedKey }
        if usedSavedKey && bonded { return .replaceSavedKey }
        return .broadcastOnly
    }

    /// Короткий ответ вместо 17B BOND-вектора — сенсор отказал. Один re-read
    /// разрешён (вектор мог ещё не быть готовым); дальше это key-exchange failure.
    /// (Kotlin `decideShortBondReadAction` 1:1.)
    static func decideShortBondReadAction(
        replyLength: Int,
        rereads: Int,
        maxRereads: Int
    ) -> ShortBondReadAction {
        if replyLength == 17 { return .accept }
        if rereads < maxRereads { return .reread }
        return .failKeyExchange
    }

    /// Хранящий ключ чистится только после подтверждённого UNPAIR
    /// (DELETE_BOND 0x01) — Kotlin `shouldClearPersistedPairKey`.
    static func shouldClearPersistedPairKey(deleteBondPending: Bool, responseStatus: Int) -> Bool {
        deleteBondPending && responseStatus == Int(commandAccepted)
    }

    /// Ответ CLEAR_STORAGE (0xF3) подтверждает reset; всё, что длиннее ACK, —
    /// не подтверждение (новое fw отвечает с ключевым материалом).
    /// (Kotlin `isClearStorageConfirmed` 1:1.)
    static func isClearStorageConfirmed(responseLength: Int, responseStatus: Int) -> Bool {
        responseLength >= 2 && responseLength <= 4 && responseStatus == Int(commandAccepted)
    }
}
