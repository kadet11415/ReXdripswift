# AiDEX Protocol — сенсоры Aidex / Linx / Lumiflex (JugglucoNG)

Протокол работы приложения с сенсорами семейства AiDEX (AIDEX, LINX, LUMI/Lumiflex,
VISTA, SMART, INDIA). Все линии = один нативный драйвер
(`Common/src/main/java/tk/glucodata/drivers/aidex/`, Kotlin), один UI-тип
`AIDEX_LINX` (SensorVendor.kt, семейство `ManagedSensorUiFamily.AIDEX`).

Правило: префикс изделия/поколения — только ярлык advertisement'а. Он никогда
не определяет стратегию ключей/паринга
(`AiDexSerialIdentity`: "product prefixes are advertisement labels, not protocol
не capabilities"). Единственный внутренний канонический неймспейс — `X-<SN>`.

---

## 1. Идентификация и бренды

- Канон. ID: `X-<SERIAL>`, serial = 8..14 символов `[A-Z0-9]` (bare, без префикса).
- Разбор advertisement (`AiDexSerialIdentity.canonicalFromAdvertisement`):
  1. префикс поколения: однобуквенный `L-<sn>` (с опц. "AIDEX " перед ним);
  2. семейный префикс `AIDEX|LINX|LUMI|VISTA|SMART|INDIA` (можно склеен: "IndiaX-22222E7T6K");
  3. fallback: bare-name ровно 11 алфавитно-цифровых символов;
  4. Fallback по MAC: `fallbackCanonicalFromAddress` = `X-<MAC без символов>`
     (проверка `storedSensorId == fallback` -> `X-<adv name>`) — для сенсоров,
     чей adv-name не распознан, но ID уже сохранён.
- Rebrands-бейдж: `"lumi"/"lumiflex"` adv-name -> бейдж `LUMI` (только
  дисплей, identity/паринг по нему не решает).
- **Manufacturer ID (SIG) в adv**: `COMPANY_ID = 0x0059` (использовать для
  фильтрации scan-результатов на iOS: `CBCentralManager` manufacturerData
  filter).
- **Known name prefix'ы** (`isAiDexDevice`): `AiDex`, `AiDEX`, `AIDEX`,
  `Linx`, `LINX`, `CGM`, `Smart-`, `IndiaX-` (использовать при сканировании
  для быстрого reject).
- `AiDexBleManager` = BLE-контроллер на сенсор (один на serial), `bindBleManager`
  в менеджере привязывает.

## 2. Ключи: два пути (legacy vs новые)

Ключи: secret (16B, F001-вызов) + IV (16B, AES-CFB128). `AiDexKeyExchange`:
`usesProvisionedPairingMaterial` = true если материал из CN-облака, иначе
производный от SN. **Это единственное различие legacy/новых сенсоров по парингу.**

### 2.1 Legacy: производные от SN (`SerialCrypto.kt`)
Порт из дизассемблирования `libblecomm-lib.so` ARM64 (`AidexXController::setSn` @0x59b04).
- `snToBytes`: serial как строка -> числовые байты (`charToNumeric`).
- secret (= F001 challenge): `MD5( map b -> (13*b+61)&0xFF )`.
- IV: `MD5( map b -> (17*b+19)&0xFF )`.
- Проверено на `2222267V4E`: secret=`4b76169576da80e4eeacf886230873d2`,
  iv=`14cb6a3a39b96c448ebc39185f70f8aa` (совпадает с HCI-трейсом).

### 2.2 Новые сенсоры: provisioned-материал (`AiDexPairingMaterial`)
- Материал = (secret, iv) по 16B, приходят **из CN-облака** (`getSnConfig`),
  хранятся в `AiDexProvisioningStore` (in-app) / `AiDexPairingMaterialFile`
  (JSON-файл: normalizeSerial + encode/decode — экспорт/импорт на устройство).
- PAIR-ключ кэшируется: `AiDexPairKeyVault` / `AiDexPairKeyBackup`.
- PAIR ключ стабилен до `DELETE_BOND` (0xF2). Session-ключ — на каждое соединение.
- Если sensor отклоняет производный (SN) вызов F001 — это **нормальный кейс
  нового сенсора**, а не баг: нужен provisioned-материал из CN.

### 2.3 Рукапока обмена ключами (`AiDexKeyExchange.run`, любой путь)
1. `Write snSecret(16B) -> F001` (challenge; secret производный или provisioned).
2. `F001 notification -> PAIR key (16B)` (стабилен до сенс. UNPAIR).
3. `Read F002 -> 17B BOND data`.
4. `sessionKey = AesCfb128.decryptBondData(BOND, PAIR, snIv)`.
5. `Write 0x10 0xC1 0xF3` (post-BOND config; plaintext) — шифр sessionKey+snIv
   (`getPostBondConfig()`).
6. Дальше: F003-кадр глюкозы и все команды F002 — шифром `sessionKey + snIv`
   (`encrypt()`/`decrypt()` — AES-CFB128).
- `reset()` при пересоединении: pairKey/sessionKey сбрасываются, BOND повтор
  каждый connect.

### 2.2.1 `snToBytes` — точное картирование (портировать 1:1)
- `charToNumeric(c)`: `'0'-'9'` -> 0..9; `'A'-'Z'` -> 10..35; `'a'-'z'` -> 10..35;
  всё остальное -> 0.
- `snToBytes(sn)`: по каждой букве -> byte `charToNumeric(c)` (без префикса
  `X-`; например `2222267V4E`).
- Transforms: **secret** = `MD5((b*13+61)&0xFF per b)`, **IV** =
  `MD5((b*17+19)&0xFF per b)` (16B каждый).
- **IV используется в 3 местах**: BOND-decrypt, F003-decrypt, F002-encrypt
  (везде вместе с соответствующим ключом: PAIR для BOND, SK для F003/F002).

### 2.2.2 AES-128 CFB128 (`AesCfb128`) — спецификация
- **CFB-128 mode** (feedback = 16 bytes, не 1 bit/квант):
  - `decrypt(ct, key, iv)`: fb = iv; на каждый блок (16B или хвост):
    `e = AES-ECB-ENCRYPT(key, fb)` (NoPadding, 1 ключ); `out = ct XOR e`;
    fb = **ciphertext**-блок (вход) — для хвоста(<16) fb не меняется.
  - `encrypt(pt, key, iv)`: то же, но fb = **output**-блок (свой ciphertext).
  - key/iv ровно 16B; длина произвольная (16, 17, 4, 21...).
- Источник: **портировано из iGlucco `AiDexCryptoEngine.swift`** — тот же
  алгоритм, искать в ReXdripswift-наследии.
- **BOND-decrypt (17B)**: `plaintext = CFB128-decrypt(bond17, PAIR, IV)`;
  `sessionKey = plaintext[0..15]`; **check**: `plaintext[16] ==
  CRC8-MAXIM(sessionKey)`; при mismatch — null (fail).
- **CRC8/MAXIM** (Dallas/Dow): полином `0x31` (x^8+x^5+x^4+1), **I/O
  reflected**; (таблица — из libblecomm-lib.so @0x3a34d, но параметры
  достаточны для реализации с нуля).
- **CRC16/CCITT-FALSE**: полином `0x1021`, init `0xFFFF`, refIn/refOut
  `false`, xorOut `0x0000`; **2-byte LE trailer на ВСЕХ F002 командах и
  ответах**. Проверочные векторы (CRC-16 одного байта-опкода, trailer LE):
  | Op | Trailer |
  |---|---|
  | 0x10 | `C1 F3` |
  | 0x11 | `E0 E3` |
  | 0x21 | `B3 D5` |
  | 0xF2 | `AD 2E` |
- MD5 — стандарт (Crypto/Incommon), hex-представление в CN-облак —
  `lowercase hex`.
- **Cross-check CFB128**: mode стандартный (AES-CFB128, RFC 3566) —
  сверить реализацию с `openssl enc -aes-128-cfb` (тот же режим).
  Если OpenSSL даёт другие байты на том же (key, iv, data) —
  реализация неверна, а не режим.

## 3. CN-облак (активация новых сенсоров)

Модуль: `AiDexCnCloudClient.kt` (+ `AiDexCnProtocol`). UI:
`Common/src/mobile/java/tk/glucodata/ui/setup/AiDexKeyManagementScreen.kt`
(поля: serial, +86 телефон, SMS-код, password, кнопки send-code / login / fetch
material / export / import).

### 3.1 Сеть
- BASE_URL: `https://china.pancares.com`, все запросы POST.
- Endpoints (`/backend/aidex-x/...`):
  - `user/sendRegisterPhoneVerificationCode` — SMS-код (login-or-register flow);
    отдельно `sendLoginPhoneVerificationCode` **не** используется (даёт biz 500).
  - `user/loginOrRegisterByVerificationCodeWithPhone` — {phone, code} -> token.
  - `user/loginByPassword` — {userName, password=MD5(pwd).hex} -> token.
  - `cgmDevice/getSnConfig` — {body:{deviceSn}, integrityData:{randomStr,timestamp,sign}}
    -> {deviceSn, publicKey, communicationKey}.
- `publicKey`/`communicationKey` = (secret, iv), 16B каждый; decodeMaterial:
  hex32 или base64, ровно 16B иначе ошибка "invalid pairing material".
- Защита от cross-sensor: если `response.deviceSn != deviceSn` ->
  `error "Server returned pairing material for another sensor"` (жёсткая).
- Таймаут 20 c; ответ `code==200` = OK, иначе `msg`/`message`.
- Материал/credentials **не логируются** (по дизайну).

### 3.2 Шифрование конверта (встроенные ключи приложения)
`AiDexCnProtocol`:
- APP_SECRET (встроен): `4ed6aa2b43a04251b6f78db47f870906`.
- sign = `MD5("deviceSn=<d>&randomStr=<r>&timestamp=<t>&key=<APP_SECRET>").toUpperCaseHex`
  (поля сорт. map, joinToString "&").
- Конверт: plain JSON -> `RSA/ECB/PKCS1Padding` публичным app-ключом
  (публичная/приватная RSA ключи встроены в код, PUBLIC_KEY / PRIVATE_KEY),
  чанками 117B (keysize-11) -> `{"encryptData": base64}`;
  декодирование ответа тем же RSA-приватным ключом.
- Заголовок: `encryption: enabled`, `X-Key-version: v2`,
  `User-Agent: "android<SDK>-<brand>-<model>,com.microtech.aidexx,1.15.1"`
  (имитация официального клиента), `Accept-Language`.
- Телефон: КНР 11 цифр `1[3-9]...`, валидация `normalizeCnPhone`
  (0086/86 prefix -> 11 цифр); `86`-префикс разрешён.

### 3.3 Гео-гейт getSnConfig (критич. для новых сенсоров)
- Возврат `getSnConfig` только КНР-IP; бэк **honors `X-Forwarded-For`**
  (клиент шлёт его).
- Клиент генерит случайный IP в известных КНР-блоках
  (`CN_ROUTING_BLOCKS`, 16 пулов: 36.96/39.128/58.14/111/112/114.80/116.192/
  120.192/124.64/180.76/182.80/202.96/218/220.160/221.192/222.16) —
  один фиксированный IP быстро rate-limit'ится, поэтому **на каждый запрос
  новый случайный КНР-IP**.
- Повтор только транзиент-коды: biz `500` = "请求过于频繁" (троттлинг,
  лечится новым IP) и `100010` (periodический China-availability miss).
  `SN_CONFIG_ATTEMPTS = 4`.
- Auth/content-ошибки (не 500/100010) — стоп без повторений
  (чтобы не маскировать реальный зацеп).
- Account-запросы (login/SMS) — **без** X-Forwarded-For, реальный IP
  (клиент официально).

## 4. BLE-протокол (F002/F003)

Крипто: AES-CFB128 (`AesCfb128`), CRC16-CCITT-FALSE (`Crc16CcittFalse`),
CRC8-MAXIM (`Crc8Maxim`). `AiDexParser` — разбор ответов,
`AiDexCommandBuilder` — сборка команд (до шифра).

### 4.1 F002 opcodes (`AiDexOpcodes`)
| OP | Name | Назн. |
|----|------|-------|
| 0x10 | GET_STARTUP_DEVICE_INFO | post-BOND config / device info |
| 0x11 | GET_BROADCAST_DATA | live-глюкоза (broadcast) |
| 0x20 | SET_NEW_SENSOR | **активация** (записывает activation datetime) |
| 0x21 | GET_START_TIME | сенсор local-время старта |
| 0x22 | GET_HISTORY_RANGE | history range |
| 0x23 | GET_HISTORIES_RAW | сырые 2B entry, 10-bit packing |
| 0x24 | GET_HISTORIES | brief 5B entry (i1, i2, vc) |
| 0x25 | SET_CALIBRATION | BG-ссылка -> сенсор |
| 0x26 | GET_CALIBRATION_RANGE | диапазон калибровки |
| 0x27 | GET_CALIBRATION | запись калибровки по index |
| 0x30 | SET_DEFAULT_PARAM | default-параметры |
| 0x31 | GET_DEFAULT_PARAM | чтение default-параметров |
| 0x32 | GET_SENSOR_CHECK | self-test |
| 0x33/0x34 | GET/SET_AUTO_UPDATE_STATUS | авто-апдейт |
| 0x35 | SET_DYNAMIC_ADV_MODE | динам. adv |
| 0xF0 | RESET (hardware maint.) | **не чейнить после lifecycle-clear** |
| 0xF1 | SHELF_MODE | полка/шиппинг |
| 0xF2 | DELETE_BOND | UNPAIR (схлопывает PAIR-ключ) |
| 0xF3 | CLEAR_STORAGE | очистить хранилище (reboot lifecycle) |

### 4.2 F003
- DATA_FRAME_LENGTH = 17B (глюкоза-кадр); STATUS_FRAME_LENGTH = 5B (keepalive).

### 4.3 Политика
- `AiDexStreamingPolicy` — стрим (live vs polling); `AiDexHistoryPolicy` — history;
  `AiDexReconnect` — пересоединение по BLE; `AiDexRuntimePolicy` — runtime.
- `AiDexTemperatureStore` — температура; `AiDexSampleJournal` — журнал сэмплов
  (raw lane i1*10 = `rawProxyMgDl`, **не** factory mg/dL);
  `AiDexSourceJournalBackup` — бэкап.
- `HistoryMerge` (native/data) — слияние history.
- `DataClasses.kt` — структуры (history row, calibration record и т.д.).

### 4.4 Wire (порт-спека — запросы и ответы)

**F001/F002/F003 — порядок и форма:**
- **F001 write** (challenge): `secret (16B)` — **как есть, без шифра**
  (ключ ещё не установлен).
- **F001 notification** (response): `PAIR key (16B)` — **как есть,
  без шифра** (стабилен до DELETE_BOND).
- **BOND**: `F002 GATT READ` (не команду — чистое чтение характеристики)
  -> `17B` (шифр: CFB128 decrypt PAIR+IV, см. §2.2.2).
- **Post-BOND config**: `[10 C1 F3]` **шифр** CFB128(SK+IV) -> запись в
  **F001** (не F002!) — первый зашифрованный пакет после обмена ключами.
- **F002 command**: plaintext = `[op, params..., crc16_lo, crc16_hi]`
  (CRC16-CCITT-FALSE **над байтами до CRC**, trailer 2B LE); затем
  **CFB128-encrypt(plaintext, SK, SN-IV)** -> запись в **F002**.
- **F002 response/notify**: `[op, ack/status(1B), payload..., (crc16_le
  — проверять, если есть)]`; echo: `sent[0] == received[0]`
  (`isHandshakeEcho`).
- **F003**: notification, **маршрутизация по длине**:
  - `17B` — data frame (glucose), layout §12, CFB128-decrypt(SK+IV);
  - `13B` — **calibration notification** (observed opcode `0x0A` —
    подтверждение обновления внутрен. калиб-состояния сенсора; **log-only,
    действие не требуется** — Android уже re-read'ит calib-records после ACK
    0x25; при несовместимом session key: `notePreAuthEncryptedTraffic`,
    drop);
  - `5B` — status/keepalive (`byte[0]` = header).
  - `17B` data frame: `byte[0]` = scale-code: `0xA1, 0xA4, 0x5B, 0xD7` —
    factor **1.0** (direct mg/dL); `0xD2` — factor **0.5**; **иной opcode — не
    error и не drop**: reject'а по opcode в Kotlin НЕТ (`AiDexParser.
    parseDataFrame` считает `glucoseMgDl = raw * (scalingFactor(opcode) ?: 1.0)`,
    `handleF003` шлёт любой CRC-valid 17B-фрейм в `handleParsedLiveReading`).
    Lumi/GX-01S-прошивки стримят live-фреймы с **opcode 0x01** — обычные
    live-кадры, принимаются с scale 1.0. (Раньше эта строка в доке ошибочно
    была «иначе → drop» — Swift-порт реализовал это как hard-reject и тем
    самым обнулял все данные сенсора; `notePreAuthEncryptedTraffic`
    относится к неудавшемуся дешифру, а не к opcode.)
  - `raw 10-bit` (pre-scaling, `GlucoseFrame`), `calibrated` = raw*scale
    (post-scaling).
- **CCCD / notify подписки** (CoreBluetooth: `setNotifyValue`):
  - `F002` + `F003` — **всегда**;
  - `F001` — **условно** (только если идёт fresh key-exchange — для
    получение PAIR key).
- **ACK**: `COMMAND_ACCEPTED = 0x01` (1-й байт payload'а = status/ack).

**Запросы (op + params, plaintext до шифра; CRC-16 trailer в конце):**
| Op | Params |
|---|---|
| 0x10 | `[0x10]` |
| 0x11 | `[0x11]` |
| 0x20 | `[year_lo, year_hi, month, day, hour, min, sec, tz_q, dst_q]` |
| 0x21 | `[0x21]` |
| 0x22 | `[0x22]` |
| 0x23 | `[offset_lo, offset_hi]` (u16LE) |
| 0x24 | `[offset_lo, offset_hi]` (u16LE) |
| 0x25 | `[offset_lo, offset_hi, glucose_lo, glucose_hi]` (указано выше, offset first) |
| 0x26 | `[0x26]` |
| 0x27 | `[index_lo, index_hi]` (u16LE) |
| 0x30 | `[totalWords, startIndex, payload...]` (chunk) |
| 0x31 | `[startIndex]` (1-based) |
| 0x33 | `[0x33]` |
| 0x34 | `[0x01] (en) / [0x00] (dis)` |
| 0x35 | `[mode]` |
| 0xF0 | `[0xF0]` |
| 0xF1 | `[0xF1]` |
| 0xF2 | `[0xF2]` |
| 0xF3 | `[0xF3]` |

**Ответы (header `[op, ack]` + payload):**
- **0x10**: 16B payload (см. §12, layout 0x10).
- **0x11 (connected broadcast / adv sample)**: payload = **broadcast
  sample** (не 17B data frame; min 7B):
  `[offset u32LE (или u16LE), ..., trend(4), glucose_lo(5), glucose_hi(6)]`
  - `offset` = u32LE[0..3] (если >=4B), валидация `0 < off <= 30д*1440`
    (MAX_OFFSET_DAYS=30); при невалидном — fallback u16LE[0..1].
  - `trend` = `byte[4]` (1B, без расшифровки — только значение).
  - `glucose` = `lo | ((carry & 0x03) << 8)` (10-bit пакетированный,
    `decodePackedBroadcastGlucoseMgDl`); fallback `byte[5]`.
  - `glucoseMgDl` = первый из {packed, fallback} в диапазоне
    **20..500** (MIN/MAX_VALID_GLUCOSE_MGDL); вне диапазона — reject.
  - **тот же парсер для GATT-ответа 0x11 и для advertising-записи**
    (broadcast-only mode, §21) — `parseBroadcastSamplePayload`.
- **0x20/0x21/0x22/0x25/0x26/0x27/0x30/0x31/0x33/0x34/0x35/0xF0/0xF2/0xF3** — см.
  §12.
- **CRC-trailer правило для F002-ответов**: послед. 2B — **валидировать как
  CRC-16/CCITT-FALSE** **над всеми предыдущими байтами** (LE-порядок:
  low byte перв. `validateResponse`); если валид — **срезать** (payload =
  `[2..size-2]`), если нет — payload = `[2..size]`.
- **0x25 ACK**: `handleCalibrationAck` (1B ack `0x01`).
- **0x33/0x34 ACK**: `handleAutoUpdateStatusAck`.
- **0x35 ACK**: `handleDynamicAdvModeAck` (`data[1]` = status).
- **0x20 ACK**: `handleNewSensorAck`.
- **0x22 range**: `[op, ack, briefStart(2..3), rawStart(4..5), newest(6..7)]`
  (все u16LE; `data.size >= 8`).
- **0x23 raw**: `[op, ack, startOffset(2..3), N*2B rows...]` (см. §12).
- **0x24 brief**: `[op, ack, startOffset(2..3), N*5B rows...]` (см. §12).
- **0x27 calibration**: `[op, ack, startIndex(2..3), N*8B rows...]`
  (`CALIBRATION_ROW_SIZE = 8`; см. §12).
- **0xF2/0xF3 ACK**: `handleDeleteBondResponse` / `handleClearStorageResponse`.
- **0xF0**: `handleResetResponse`.
- **0xF1**: **нет** отдельного handler (fire-and-forget, без ответа).
- **0x32**: **нет** отдельного handler (не используется в текущем
  потоке).

## 5. Реестр и жизненный цикл

`AiDexNativeSensorManager` (780 строк):
- Персистентность: `loadFromPersistence()` / `addSensor` / `removeSensor` /
  `setMainSensor` / `isMainSensor`.
- Здоровье: `onGlucoseReceived` на reporting-serial метит healthy другие
  (`checkOtherSensorsHealth`); `shouldWriteHealth` / `resetHealthWriteFlags`.
- Скан-матчинг: `matchScanResult` / `matchDeviceName` (имя/serial/MAC fallback).
- BLE-привязка: `bindBleManager` / `getBleManager` (один `AiDexBleManager` на serial).
- `reconcile` — примирение авторитетных serial'ов с локальным списком.
- `SensorState` (data class per serial) — состояние сенсора.

## 6. Активация сенсора (новые, через CN)

Полный порядок (end-to-end):
1. **Скан**: discovery по advertisement (name/serial, MAC fallback) -> `matchScanResult`.
2. **Попытка паринга**: SN-производные (legacy). Если F001-вызов отклонён ->
   новый сенсор, идти в пункт 3.
3. **Вход в CN-облак** (`AiDexKeyManagementScreen`): +86 телефон -> SMS-код
   (`sendRegisterPhoneVerificationCode`) -> `loginOrRegister...ByPhone`
   (или `loginByPassword`) -> x-token.
4. **Запрос материала**: `getSnConfig(serial, token)` (4 попытки, случайные КНР-IP,
   только 500/100010 ретраи). Ответ `publicKey`+`communicationKey` ->
   `AiDexPairingMaterial(secret, iv)` -> `AiDexProvisioningStore` / файл.
5. **Повтор паринга**: F001 challenge = provisioned secret -> PAIR-ключ (F001 notif)
   -> BOND (F002) -> sessionKey (AES-декод) -> post-BOND `10 C1 F3` -> OK.
6. **Активация**: `SET_NEW_SENSOR` (0x20) с activation datetime
   (app задаёт start-время синхр.).
7. **Default-параметры** (опц.): `SET_DEFAULT_PARAM` (0x30) из каталога
   (snapshot/импортированный, §7).
8. **Стрим**: `GET_BROADCAST_DATA` (0x11) live + F003 17B-кадры; история
   `0x22/0x23/0x24`.
9. **Калибровка**: 0x25 (manual BG-reference) или Adaptive V2 (§8);
   cf/offset держатся `AiDexRetainedCalibration`.
10. **Сброс/UNPAIR**: `DELETE_BOND` (0xF2) -> `CLEAR_STORAGE` (0xF3) или
    `RESET` (0xF0, только hardware-maint. — не чейнить после lifecycle-clear).

## 7. Калибровка и default-параметры

- **Записи калибровки** (on-board память, `AiDexDriver.CalibrationRecord`):
  index, timeOffsetMinutes, referenceGlucoseMgDl, cf, offset, isValid,
  timestampMs = `sensorstartmsec + timeOffsetMinutes*60_000`. Retained-хранилище:
  `AiDexRetainedCalibration`.
- Драйвер объявляет `supportsManualCalibration = true`.
- **DP-каталог** (`AiDexDefaultParamProvisioning`):
  - `AiDexOfficialDpCatalogSnapshot` — **встроенный** каталог factory-дефолтов по SN
    (489 строк, статичный снапшот).
  - `AiDexDpCatalogProvider` — merge: `snapshotEntries()` + `importedEntries()`
    (пользовательский JSON-импорт, SharedPreferences `AiDexDpCatalogPrefs`);
    LinkedHashMap merge по ключу (импорт override'ит snapshot).
  - `entries()` = merged; `ImportResult`/`CatalogState` — результат импорта.
  - `SET_DEFAULT_PARAM` (0x30) пишет merged-значения на сенсор.

## 8. Оценка глюкозы (алгоритмы)

`rawProxyMgDl = i1*10` — app-хранённая lane, **не** factory mg/dL (явно в
коммент `AiDexAdaptiveSample`). Фактическая калибровка factory не доступна
для новых сенсоров (проприетарный factory-алгоритм не реконструируется).

`AiDexAlgorithmSelection` (per-sensor, persist id):
- `STOCK(0, false, false)` — stock.
- `ADAPTIVE_V2(8, true, false)` — Adaptive V2.
- `ADAPTIVE_V2_CALIBRATED(9, true, true)` — + калиброванный.

`AiDexAdaptiveV2` (557 строк) — raw->glucose:
- `AiDexNormalization.FACTORY_ASSISTED` — **гибрид**: учит медленный raw->glucose
  curve на паре raw/factory (не реконструкция factory-алго).
- `AiDexNormalization.REFERENCE_ONLY` — **не** читает factory-глюкозу, ждёт timely
  reference (вручную).
- `AiDexAdaptiveSample` содержит `sessionStartMs` (activation/reset identity,
  **не** infered из глюкозы) + `temperatureC`.
- Состояние persist (CRC32 в binary state-файле, `DataInput/OutputStream`).
- `AiDexAlgorithmController/References/Runtime` — runtime-контроль.

## 9. Файловая карта (Common/src/main/.../drivers/aidex/)

- identity: `AiDexSerialIdentity.kt`
- crypto/keys: `native/crypto/{SerialCrypto, AesCfb128, Crc16CcittFalse, Crc8Maxim}.kt`,
  `native/protocol/{AiDexKeyExchange, AiDexPairingMaterial, AiDexPairKeyVault, AiDexPairKeyBackup}.kt`
- CN-облак: `AiDexCnCloudClient.kt` (клиент + `AiDexCnProtocol`)
- provisioning: `AiDexProvisioningStore.kt`, `AiDexPairingMaterialFile.kt`
- DP: `AiDexDefaultParamProvisioning.kt`, `AiDexDpCatalogProvider.kt`, `AiDexOfficialDpCatalogSnapshot.kt`
- BLE: `native/ble/{AiDexBleManager, AiDexGattCallbacks, AiDexNativeSensorManager, AiDexReconnect, AiDexStreamingPolicy, AiDexHistoryPolicy, AiDexRuntimePolicy}.kt`,
  `native/protocol/{AiDexOpcodes, AiDexCommandBuilder, AiDexParser, data/DataClasses, HistoryMerge}.kt`
- алгоритм: `adaptive2/{AiDexAdaptiveV2, AdaptiveV2Estimate/Estimator/Modes/Observation/State, AiDexAlgorithmSelection/Controller/References/Runtime}.kt`
- stores: `AiDexTemperatureStore.kt`, `AiDexSampleJournal.kt`, `AiDexSourceJournalBackup.kt`, `AiDexRetainedCalibration.kt`
- scan: `AiDexScanReceiver.kt`
- driver interface: `AiDexDriver.kt` (323 строки, `ManagedBluetoothSensorDriver` + `ManagedSensorMaintenanceDriver`)
- UI: `Common/src/mobile/java/tk/glucodata/ui/setup/AiDexKeyManagementScreen.kt` (467 строк)

## 10. Известные замечания / ловушки

- **Geo-гейт getSnConfig** (КНР-IP) — единственный обязательный сервисный
  вызов; login/SMS — без X-Forwarded-For (реальный IP).
- **SMS-флей** — login-or-register (один поток); `sendLoginPhoneVerificationCode`
  biz 500 (не использовать).
- **Product-prefix не протокол** — только adv-ярлык; hardware-пачки меняли
  имена, identity/паринг должны быть стабильны.
- **Cross-sensor guard**: `response.serial != requested` -> жёсткая ошибка
  (материал другого сенсора не использовать).
- **Тротлинг 500** = новый IP; `100010` = China-availability (ретрай допустим).
- **RESET (0xF0)** — hardware-maint. only, чейнить **запрещено** после
  lifecycle-clear.
- **rawProxyMgDl** = хранённая lane i1*10, не factory-калибровка
  (явно в `AiDexAdaptiveSample` док-коммент).
- **APP_SECRET + RSA-ключи** встроены в `AiDexCnProtocol` — не логировать,
  не коммитить в логи.

---

## 11. GATT-слой (`AiDexBleManager`, 7492 строк)

- Кастом-сервис `F000` = `0000181f-0000-1000-8000-00805f9b34fb`:
  - `F001` = `0000f001-...` — запись F001 challenge (secret 16B), notification -> PAIR-ключ;
  - `F002` = `0000f002-...` — команды/запросы (read/write), BOND/ответы;
  - `F003` = `0000f003-...` — notification: data-frame 17B / status 5B.
  - На каждый char — CCCD (очередь `cccdQueue`, `pendingBondedCccdUuid`);
  - после key-exchange при смене bond (bonded / fresh bond) — re-enable live-CCCD
    (`shouldRefreshLiveCccdsAfterKeyExchange`).
- Стандартный DIS `0x180A`: Model Number `2A24`, Software Rev `2A28`, Manufacturer `2A29`
  (идентификация устройства).
- Кастом CGM-характеристики: `2AAА` (session start) и `2AAB` (session run) —
  читать **до первого live**: `shouldReadSessionCharacteristicsBeforeFirstLive`
  (true если post-reset-активация / авто-активация, либо свежий bond, либо нет
  persisted history-state).
- **MTU**: сенсор сам инициирует повторный MTU-обмен сразу после connect;
  `MTU_SETTLE_BEFORE_CCCD_MS = 750` — ждать стаскивания перед первым CCCD-write
  (иначе discovery/CCCD ложится поверх pending MTU) ;
  `MTU_CALLBACK_FALLBACK_MS = 2000` — fallback-timer (guard двойного discovery,
  `mtuExchangeCrossedPendingCccd`).
- **Bond**: `bondState` проверяется перед критичными шагами; решения в
  `AiDexRuntimePolicy.decidePairKeyStartAction` (bond-зависимый start PAIR).
- Операционная очередь `GattOp` (Write/Read) + `AiDexGattCallbacks`:
  `beginOperation`/`canStartOperation`/`completeOperation`/`timeoutOperation`
  (созданный, id-проверка при потреблении — reset может выкинуть pending message),
  guard двойного discovery.
- Internal states (значения enum):
  `StartupControlStage {IDLE, WAIT_DYNAMIC_ADV_ACK, WAIT_AUTO_UPDATE_ACK,
  COMPLETE, FAILED}` (после CCCD: dynamic-adv 0x35 -> auto-update 0x34 ->
  COMPLETE/FAILED);
  `HistoryPhase {IDLE, DOWNLOADING_CALIBRATED(0x23), DOWNLOADING_RAW(0x24)}`
  (0x23 = calibrated-глюкоза, 0x24 = ADC/raw);
  `PostCcdcFollowUp {NONE, ENTER_STREAMING, RESUME_STREAMING}`;
  `PendingInvalidSetupRecovery {NONE, RECONNECT}`.
- BOND-read: `BOND_VECTOR_LENGTH = 17`; re-read короткого:
  `BOND_READ_MAX_REREADS = 1`, delay 400ms (`decideShortBondReadAction`);
  ACK: `COMMAND_ACCEPTED = 0x01`, `MAX_ACK_LENGTH = 4`; invalid-setup ->
  bond-reset порог: `INVALID_SETUP_BOND_RESET_THRESHOLD = 2`.
- **Все timing'ы BleManager (мс)** — полный набор констант (для порта 1:1):
  | Конф. | Значение | Назначение |
  |---|---|---|
  | GATT_OP_TIMEOUT_MS | 15 000 | watchdog: нет callback -> `recoverFromStaleConnectionState` (post-reset clear-storage — особый путь: `abandonClearStorageReset`/`completePostResetReconnect`) |
  | STALE_CONNECTION_RECOVERY_FALLBACK_MS | 3 000 | fallback recovery old-connection |
  | GATT_WRITE_RETRY_DELAY_MS | 200 | delay между GATT-write retry'ми |
  | GATT_OP_MAX_RETRIES | 10 | max retries GATT-операции |
  | NO_RESPONSE_ADVANCE_MS | 35 | advance по «no-response» |
  | BONDING_PAUSE_TIMEOUT_MS | 15 000 | пауза во время bonding |
  | DISCOVERY_RETRY_DELAY_MS / DISCOVERY_MAX_RETRIES | 1 500 / 2 | retry service discovery |
  | MTU_CALLBACK_FALLBACK_MS | 2 000 | guard двойного discovery (`mtuExchangeCrossedPendingCccd`) |
  | MTU_SETTLE_BEFORE_CCCD_MS | 750 | settle перед CCCD-write |
  | KEY_EXCHANGE_TIMEOUT_MS | 35 000 | timeout key-exchange |
  | SETUP_STALL_TIMEOUT_MS | 25 000 | stall setup |
  | SETUP_BONDING_STALL_TIMEOUT_MS | 35 000 | stall setup во время bonding |
  | PRE_AUTH_ENCRYPTED_TRAFFIC_TIMEOUT_MS | 5 000 | pre-auth encrypted frames |
  | PRE_AUTH_ENCRYPTED_TRAFFIC_MIN_FRAMES | 3 | мин. frames pre-auth |
  | CCCD_WRITE_CALLBACK_TIMEOUT_MS | 2 500 | callback CCCD-write |
  | CCCD_WRITE_CALLBACK_MAX_EXTRA_WAITS | 1 | max extra waits |
  | HISTORY_PAGE_TIMEOUT_MS | 25 000 | timeout history-страницы |
  | HISTORY_REQUEST_DELAY_MS | 80 | delay между history-запросами |
  | CLEAR_STORAGE_QUIET_WINDOW_MS | 12 000 | window после CLEAR_STORAGE |
  | POST_RESET_RECONNECT_DELAY_MS | 5 000 | delay reset->reconnect |
  | EXPECTED_LIVE_INTERVAL_MS | 60 000 | ожидаемый интервал live |
  | EXPECTED_LIVE_GRACE_MS | 20 000 | grace после last reading |
  | NO_STREAM_WATCHDOG_MS | 80 000 | (= 60 000 + 20 000) |
  | CONNECTED_BROADCAST_REQUEST_WAIT_MS | 30 000 | wait connected broadcast |
  | INITIAL_HISTORY_REQUEST_DELAY_MS | 65 000 | delay перед первым history-request |
- `handlePendingInvalidSetupRecovery` — flow: INVALID_SETUP после N=2
  failed bond-resets -> RECONNECT (full re-dial).
- GATT-op watchdog: on fire -> queue clear, **retire transport** (late
  callback не отличить от retry, т.к. не может — late callback не может
  различить retry от timed-out dispatch) — `gattOpWatchdog`.

## 12. Фреймы и структуры (DataClasses / Parser)

- **DATA 17B** (`classifyFrame` по длине; `parseDataFrame`), точный layout:
  - `byte[0]` = opcode (определяет scaling и тип фрейма);
  - `bytes[1..3]` — **неопознанные** (observed non-zero, vary per frame);
  - `bytes[4..5]` = `timeOffsetMinutes` (u16 LE) — минут с старта сенсора
    (тот же u16, что history 0x23/0x24/0x27 и калиб-пейлоды; ранее был ложный
    парсинг как u32-секунды на bytes[1..4] — "garbage timing bytes" workaround,
    см. коммент Parser);
  - `bytes[6..7]` = `glucosePacked` (u16 LE), `glucose = packed & 0x03FF`
    (10-bit, 0..1023);
  - `i1 = u16LE([8..9]) / 100`, `i2 = u16LE([10..11]) / 100` (raw-каналы);
  - `CRC-16 = u16LE([15..16])` (проверка);
  - `isValid`: не sentinel и в диапазоне; saturation-фильтр — ADC `>= 1023`
    (calibrated фильтрует; raw-lane может быть выше).
  (raw lane `i1*10` (x10) = app-хранённый `rawProxyMgDl`, см. §8.)
- **STATUS 5B**: `byte[0]` = status-indicator (keepalive/live).
- **F003 i2-канал** = skin-температура, °C (проверена на co-worn Sibionics
  сенсоре); зеркалится в `AiDexTemperatureStore` (display-only, не трогает
  glucose-хранилище/calibration).
- **0x10 response** (payload 16B, `parseStartupDeviceInfo*`):
  `[u16 status (==0) | fw_major(2) fw_minor(3) | hw_major(4) hw_minor(5) |
  wear_days(6) | (7) model code | model ASCII 8..NUL-terminated]` ->
  `StartupDeviceInfo(firmwareVersion "maj.min", hardwareVersion, wearDays,
  modelName)`. Frame-варианты: payload от 1, затем от 2; ACK-вариант:
  `frame[1]==0x01` и body от 2, non-zero model code допустим (пример: Lumi
  GX-01S fw 1.7.1 дал 0x8000); имя модели должно быть printable ASCII.
- **0x21 / 2AAA start-time payload** (shared `parseLocalStartTimePayload`,
  min 7B): `year u16LE[0..1], month[2], day[3], hour[4], min[5], sec[6],
  tzQuarters[7] (>=8), dstQuarters[8] (>=9)`; allZeros принимается;
  plausibility: year 2020..2040 и т.д.
- **0x25 wire**: `[0x25, offset_lo, offset_hi, glucose_lo, glucose_hi,
  CRC16_lo, CRC16_hi]` — offset **first**, glucose **second** (подтверждено
  дизассемблером).
- **0x20 wire**: `[year_lo, year_hi, month, day, hour, min, sec,
  tz_quarters, dst_quarters]` (те же поля что 0x21, year LE).
- **DP-chunk** (0x30/0x31 response): `[lead, totalWords, startIndex(1-based),
  raw...]`; continuation = `startIndex + rawChunk.size/2` (2-байтовые слова).
- **History RAW (0x23) response**: payload = `[startOffset u16LE,
  N*2B rows...]`:
  - row: `b0, b1`; `glucose = b0 | ((b1 & 0x03) << 8)` (10-bit pack, 0..1023);
  - status bit: `b1 & 0x04` (sentinel = 1023 — no reading);
  - `timeOffsetMinutes = startOffset + i` (row i, 2B строка).
- **History brief (0x24) response**: payload = `[startOffset u16LE,
  N*5B rows...]`:
  - row: `[i1_lo, i1_hi, i2_lo, i2_hi, vc]`; `i1 = u16LE/100`,
    `i2 = u16LE/100`, `vc = u8/100`;
  - `rawValue = i1*10` (соответствует Android raw-lane — `rawProxyMgDl`);
  - `sensorGlucose = i1 * 18.0182` (i1 как mmol/L -> mg/dL);
  - invalid row: `i1==0 && i2==0 && vc==0` (skip);
  - `timeOffsetMinutes = startOffset + i`.
- **Startup**: `parseStartupDeviceInfo{Frame,Payload}`, `parseLocalStartTimePayload`,
  handshake-эхо `isHandshakeEcho`.
- **Default param**: чанки (`parseDefaultParamChunk` / `appendDefaultParamChunk` /
  `defaultParamRawHex`).
- **Calibration (0x27) response**: payload = `[startIndex u16LE,
  N*8B rows...]`:
  - row: `[timeOffset u16LE, reference u16LE, cfRaw u16LE, offsetRaw s16LE]`;
  - `cf = cfRaw/100`, `offset = offsetRaw/100` (signed);
  - `index = startIndex + i`;
  - `timeOffsetMinutes`, `referenceGlucoseMgDl` — как есть;
  - `isValid` — определяется контекстом (index в range и т.д.).
- **Calibration range (0x26)**: `[startIdx u16LE, newestIdx u16LE]`
  (response 2 u16 — start/newest по комменту Opcodes).

## 13. Streaming (no-stream recovery, `AiDexStreamingPolicy`)

- Лестница при молчании live (по одному разу на шаг, с guard'ами):
  `KEEP_WAITING` (свежий broadcast идёт / history грузится) ->
  `REQUEST_CONNECTED_BROADCAST` (connected-broadcast request 0x11) ->
  `REQUEST_HISTORY_REFRESH` (есть session-fallback данные) ->
  `REFRESH_LIVE_CCCDS` (перевключить CCCD live) -> `RECONNECT`.
- **Watchdog** (no-stream): `delay = max(default, latestReadingMs + expectedLiveIntervalMs
  + graceMs)` — history-aware (если live-фрейм только что был — даём интервал+grace).
- До первого live: read session-чары `2AAA/2AAB` (см. §11).

## 14. История (`AiDexHistoryPolicy`)

- `planInitialDownload`: курсоры `rawNextIndex` / `briefNextIndex` (persisted),
  `downloadStartIndex`; при `sourceRepairOffset` (из `timeMs`:
  `offset = timeMs/60000 - sensorStartMs/60000`) — курсоры откатываются на repair.
- **Dedupe live/history**: скипается **только точный live-поддерживаемый оффсет**
  (более свежие оффсеты на reconnect могут легитимо не иметь прямого F003 —
  skip >= cutoff уронит реальную backfill-строку).
- `shouldEmitCatchUpBroadcast` — catch-up broadcast при пропуске.
- Post-reset карантин: `POST_RESET_HISTORY_RESIDUE_GRACE_MINUTES = 30`
  (`shouldQuarantinePostResetHistoryRange`).
- `isWithinWearDuration(wearDays)` — wear-time окно считается.
- `OFFSET_TIMESTAMP_FUTURE_SLACK_MS = 5 min` — слегка future-офсеты принимаются.

## 15. Runtime / recovery (`AiDexRuntimePolicy`, `AiDexReconnect`)

- Решения next-action при сбоях: `decidePairKeyStartAction` (bond-зависимый),
  `decideKeyExchangeFailureAction`, `decideInvalidSetupRecoveryAction`
  (pending-стейт до CCCD-ready), `decideMissingCccdCallbackAction`.
- Startup device info: `STARTUP_DEVICE_INFO_MAX_ATTEMPTS = 3`,
  `RETRY_SPACING_MS = 30 s`.
- `AiDexReconnect` (313 строк) — **полная конфигурация** (мс, 1:1 для порта):
  - base 2 500 (1st attempt = base + adaptive bump); 2nd attempt —
    `reconnect2ndFallbackMs` 5 000; дальше чередует (adaptive/2nd-fallback);
  - adaptive: `reconnectAdaptiveStepMs` 400 (за slow-streak), cap
    `reconnectMaxAdaptiveMs` 5 000, `maxSlowStreaks` 5;
  - competing session: `competingSessionDelayMs` 20 000
    (`competingSessionDelay`);
  - auth-failure: base 2 000, ×2 на каждый fail, max 60 000; max 5 подряд
    -> lockout / broadcast-only mode (`isBroadcastOnlyMode`);
  - bond-failure: max 3 подряд -> bond lockout 5 min
    (`bondLockoutUntilMs`, `onBondFailure`, `isBondLockoutActive`,
    `bondLockoutRemainingMs`);
  - `serviceDiscoveryTimeoutMs` 12 000 (`isServiceDiscoveryTimedOut`);
  - `staleSetupTimeoutMs` 35 000 (`isSetupStale`);
  - connect-attempt: base 55 000 + adaptive 10 000 за slow-streak,
    max 75 000 ("slow" = connect callback age > 15 000 — 
    `recordConnectCallbackAgeMs`/`recordSlowExecuteConnect`/
    `recordFastExecuteConnect`, `maxSlowStreaks` 5);
  - state (mutable): `softAttempts`, `slowExecuteStreak`, `authFailureCount`,
    `bondFailureCount`, `bondLockoutUntilMs` (0 = нет lockout),
    `isBroadcastOnlyMode`.
- `onConnectionSuccess`/`onBondSuccess` — сброс счётчиков; `reset()` — полный
  сброс при смене сенсора.

## 16. Stores, identity, factory

- `AiDexRetainedCalibration.integrates(context, sensorId, isRaw)` — интеграция
  калибровки (raw / calibrated lane).
- `AiDexScanReceiver` — BroadcastReceiver системных scan-объявлений
  (`onReceive` -> match-скан).
- `AiDexSourceJournalBackup` — файлы `filesDir` (backup/restore journal'ов на
  сенсор, path-pattern `isJournalPath`).
- `AiDexManagedSensorIdentityAdapter` — identity для UI/runtime:
  `nativeAlias`, canonical/stable ID, persisted sensor IDs, `matchesCallbackId`,
  `createManagedCallback` (SuperGattCallback + dataptr).
- `AiDexNativeFactory` — `createBleManager(serial, dataptr)` (BleManager на serial),
  `installProvisionedPairingMaterial` / `clearProvisionedPairingMaterial`,
  `isNativeAiDex`, `isBroadcastOnly` (режим только broadcast).

## 17. Mapping response → handler (BleManager)

F001/Bond chain:
- F001 ответ -> `handleF001Response`
- bond read -> `handleBondReadReply` / `handleBondData`
- failure chain -> `handleKeyExchangeFailure`
F003 (data): `handleF003` -> by frame type:
- live -> `handleParsedLiveReading`
- status -> `handleStatusFrame`
- calibration notification frame -> `handleCalibrationNotificationFrame`
F002 response:
- ack -> `handleF002Response` (ack byte `0x01`)
- 0x10 -> `handleStartupDeviceInfoResponse`
- 0x21 -> `handleLegacyStartTimeResponse` (+ `handleLegacyCombinedMetadataResponse`)
- 0x11 -> `handleBroadcastDataResponse`
- 0x20 -> `handleNewSensorAck`
- 0x22 -> `handleHistoryRangeResponse`
- 0x23 -> `handleHistoryRawResponse`
- 0x24 -> `handleHistoryBriefResponse`
- 0x25 -> `handleCalibrationAck`
- 0x26 -> `handleCalibrationRangeResponse`
- 0x27 -> `handleCalibrationResponse` (+ `handleAutoUpdateCalibration`)
- 0x33/0x34 -> `handleAutoUpdateStatusAck`
- 0x35 -> `handleDynamicAdvModeAck`
- 0x30/0x31 -> `handleSetDefaultParamResponse` / `handleDefaultParamResponse`
- 0xF0 -> `handleResetResponse`
- 0xF2 -> `handleDeleteBondResponse`
- 0xF3 -> `handleClearStorageResponse`
- 0x32 `GET_SENSOR_CHECK` — declared in Opcodes, **no dedicated handler**
  in the current BleManager flow.
- 0xF1 `SHELF_MODE` — no dedicated handler (no response expected).
BLE/chain:
- `handleConnectionStateChange`, `handleDescriptorWrite` (CCCD),
  `handleCharacteristicReadValue`, `handleCGMSessionStartTime` (2AAA)
- `startKeyExchangeForCurrentConnection` / `startSavedPairKeyExchange`
  (PAIR key from Vault) / `startFreshPairKeyExchange`
- `handleWriteFailure` / `handleReadFailure`

## 18. Wear-profile (rated-износ)

`AiDexWearProfile`:
- Rated-износ comes from the default-parameter catalog: `settingContent`
  has **uint32 LE seconds** at byte offset 4 (`WEAR_SECONDS_OFFSET = 4`),
  must be divisible by 86_400.
- Models: `GX-01S` = 15 days, `GX-02S` = 10 days, `GX-03S` = 8 days,
  `GXXXS` files = 7/14/16 days.
- `ratedDaysBySettingType` — group-by settingType (same for all firmware of a model).
- Important: wear-profile **does not decide** at what time the measurements stop
  (that is the `wear_days` byte of the startup `0x10`).
- Used in `isWithinWearDuration` (HistoryPolicy) — history filter by wear period.

## 19. PAIR-ключ persistence (Vault / Backup)

`AiDexPairKeyVault`:
- Storage: 3 tiers — `AiDexPairKeysPrimary` + `AiDexPairKeysRecovery` prefs
  + legacy migration from `AiDexNativePrefs` (entry `pairKey_v1_<bareSerial>`).
- `saveIfAbsent` / `saveValidated` — save the PAIR key (16B).
- `fingerprint` — for diagnostics (not a full key).
- `exportPayload` / `importPayload` — export/import of the key between devices.
- `clearAfterConfirmedUnpair` — clean **only after UNPAIR confirmed**.
`AiDexPairKeyBackup`:
- Backup file format: magic `JUGGLUCONG_AIDEX_PAIR_KEY`, version `1`, 16B key,
  serial checksum (`checksum(bareSerial, keyHex)`, hex).
- `startSavedPairKeyExchange` — on reconnect, if there is a PAIR key in the
  Vault, use the saved one (skipping the F001 challenge).

## 20. DP diagnostics / guarded-apply

`AiDexDefaultParamProvisioning`:
- `compareKnownCatalog(currentRawHex, modelName, firmwareVersion)` ->
  list of `Comparison` (diff of current values with known variants).
- `diagnoseCurrentDefaultParam` — diagnosis of the current default parameters
  against the catalog.
- `planGuardedApply` — **plan a guarded apply**: read current -> compare ->
  write via 0x30 with verification.
- `normalizeCurrentVariants` — current `CurrentVariant`.
- `ByteDiff` / `diffSummary` — per-byte differentiation.
- `CatalogEntry` (settingType, settingContent), `CatalogSource` enum
  (snapshot vs imported).
- Used for diagnostics of the sensor's default parameters and safe (guarded)
  write via 0x30.

## 21. Broadcast-only mode

`AiDexNativeFactory.isBroadcastOnly` — mode where the sensor does not open a
GATT session, the app runs its **own** `BluetoothLeScanner`:
- `startBroadcastScan(reason, continuous)`:
  - match by scan record on address or advertised name
    (`aiDexExtractLocalName`, `aiDexDeviceNameMatchesSerial`);
  - parse the sample payload from the scan record
    (`parseBroadcastSamplePayload` -> `processBroadcastPayload` ->
    `markStartupControlComplete("broadcast-<source>")`).
- Continuous scan: `shouldContinueBroadcastScanning()`;
  post-UNPAIR-suppressed: `postUnpairBroadcastScanSuppressed`;
  recovery on stale: `recoverAlarmScanIfStale("start-<reason>")`.
- Live in broadcast-only mode comes via scan, not via F003 CCCD.

## 22. Inside `AdaptiveV2` (IMM-фильтр, 2 865 строк пакета)

Архитектура: **IMM (Interacting Multiple Model)** над 4 гипотезами
`AdaptiveV2Mode {STEADY, DYNAMIC, ARTIFACT, DRIFT}`:
- STEADY/DYNAMIC — quiescent (quiet) vs реальное движение глюкозы;
- ARTIFACT — «датчик сдвинулся, глюкоза нет» (safety-критичный: отличить
  rapid-fall от ложного провала сенсора);
- DRIFT — медленный сдвиг sensitivity/offset (не путать с движением глюкозы).

State: N = 7 (Kalman; 3 glucose-состояния B/I/V — gain B/I/V; rate/velocity).
- transition matrix — **per minute** (не композируется: Q(dt) != Q(1)*dt для
  coupled-состояний); gap — bounded substeps (20-мин gap: mode identity не
  должна быть persistent как для одной минуты).
- re-initialization: posterior слишком широка (порог) -> clean start
  (сенсор мог быть re-inserted; честность важнее ложной непрерывности).

Update cycle (`mix` -> `predict` -> `updateWithChemical`):
- **Student-t robust downweight** innovation, gated on evidence:
  telemetry-disturbance + vendor-quality-флаг
  (`TelemetryArtifactPrior`: `impedance*0.22 + vendor*0.30`, cap 0.40)
  + reversal-evidence; no evidence -> face value, strong evidence -> full
  Student-t suppression (comment: 1.2 mmol/min ramp — 67% движения,
  -0.85 ниже сигнала; именно такое поведение фильтр намеренно даёт).
- mode posterior ∝ predicted × likelihood; mixing-вес из transition matrix;
  `MAX_TRANSFER_FRACTION = 0.85`; states relax to learned priors (не к нулю).
- **Reversal-detection**: два больших противоположных innovation'а подряд
  -> spike; `reversalEvidence` — коррекция **до** складывания доказывающего
  сэмпла (иначе correction уйдёт на минуту позже — то, что фильтр не
  должен делать).

Uncertainty (не «сведение», а контракт):
- `surpriseVariance` — медиану двигать немедленно, interval расширить;
  decay быстрая (confirmed move перестаёт быть «непредсказанным»);
- `gapVariance` — неопределённость отсутствующих сэмплов: high-gain после
  hole НЕ должен её схлопывать; decay по re-established сэмплах;
- `episodeDistrust` — distrust из прошлых минут (намерено **не** включает
  reversal-evidence текущего сэмпла — доказывающий сэмпл надёжный).

Сабмодели (1:1 во время порта): `AdaptiveV2TelemetryModel`,
`AdaptiveV2NoiseModel`, `AdaptiveV2LagEstimator` (lag = delay ответа
сенсора); `vendorSensitivityDrift` (diagnostic trace), `factorySensitivity`
/ normalized sensitivity clamp 0.5..3.5 -> `DEFAULT_SENSITIVITY`.

Diagnostics: `UpdateTrace` (per minute: observation, predicted, innovation,
rawWeight, effectiveR, priorVariance, gain B/I/V, b/i/v, lagTerm, motion,
artifact; пишется каждый сэмпл, читается тестами); `AdaptiveV2Estimate` —
`GaussianMixture1D` (cdf/quantile/median, `erf`, `normalQuantile`),
`probabilityBelow(thresholdMmol)` (P(low)), `toCsvRow`.

Signal: `AiDexSignalNormalizer` — factory-ratio, `targetLogScale` = median
ratio, `bootstrapSpread`, `fitOffset`; `AiDexReferenceCorrection`
(`offsetMmol`/`varianceMmol2` с time-weighting от references).

Persistence: `snapshot()`/`restore()` (binary) + `DataOutputStream`/
`DataInputStream` `writeTo`/`readFrom` + **CRC32**.

Modes (normalization, §8):
- FACTORY_ASSISTED — hybrid: учит медленный raw->glucose curve от
  raw/factory пар (не реконструкция factory-алго).
- REFERENCE_ONLY — не читает factory-глюкозу, ждёт timely reference.
`rawProxyMgDl = i1 * 10` (i1 = u16LE/100) — app lane, **не** factory-кал (
comment `AiDexAdaptiveSample`).

**Порт**: 2 865 строк **1:1**, не re-derive (фильтр тюниться на real-data;
1.2 mmol/min ramp — «67% of each minute's move» в comment
`updateWithChemical`); float/double-семантику сохранить; persistence —
byte-compatible (CRC32) или Codable + version (и тогда restore
переписать — иначе snapshot-совместимость теряется).

## 23. Scope of the doc (дораскрывать line-by-line во время порта, 1:1)

- `2AAB` (session run) — Android **не** deep-parset; читать value при
  порте (diagnostics-уровень), сопоставить с Android при расхождении.
- Внутренние константы AdaptiveV2-сабмоделей (`AdaptiveV2TelemetryModel`,
  `AdaptiveV2NoiseModel`, `AdaptiveV2LagEstimator`) — математика внутри
  файлов; port 1:1 (architecture/режим/weight'ы раскрыты в §22).
- `handleConnectionStateChange` (~600 строк) / `handleWriteFailure` /
  `handleReadFailure` / `handlePendingInvalidSetupRecovery` — структура +
  **все** константы/enum/timing'ы раскрыты (§11, §15, §17); кодовая
  реализация читать line-by-line во время порта.
- `drivers/mq/MQCloudClient` и `ICanHealthCloudCode` — **отдельные**
  vendor-облаки (maintenance cloud / iCan Health), не часть AiDex-протокола;
  при порте **не** объединять с AiDex-Cn-облак.
- **Решено в этот проход (закрыто, но проверять при порте)**:
  - `parseBroadcastSamplePayload` — задокументирован (§4.4, 0x11/adv).
  - 13-байтовый F003 (calibration notification, opcode 0x0A) —
    задокументирован (§4.4).
  - Scaling opcodes 17B data frame (A1/A4/5B x1.0, D2 x0.5) —
    задокументирован (§4.4).

## 24. Port to Swift (JugglucoNG → ReXdripswift)

**Module → iOS (Swift) mapping:**

| Kotlin-модуль | Swift-соотв. |
|---|---|
| `crypto/{SerialCrypto, AesCfb128, Crc16CcittFalse, Crc8Maxim}` | Port 1:1; **AES-128 CFB128** — CryptoKit'а CFB128 нет (готового),
  нужен **custom CFB128** (или CCAES/CCB-based); CRC16-CCITT-FALSE,
  CRC8-MAXIM, MD5 (Crypto); **test vector**: serial `2222267V4E` →
  secret `4b76169576da80e4eeacf886230873d2`, iv
  `14cb6a3a39b96c448ebc39185f70f8aa` (проверка parity'ы) |
| `protocol/{AiDexKeyExchange, AiDexPairingMaterial, AiDexPairKeyVault,
   AiDexPairKeyBackup}` | 1:1; PAIR-ключ — **Keychain** (iOS нет "recovery copy"
  как на Android prefs'ы — design-решение: Keychain + file-backup в
  Application Support, и тогда Vault→Keychain-adapter) |
| `AiDexCnCloudClient` + `AiDexCnProtocol` | `URLSession`; **RSA-1024
  PKCS1** (SecKey, `.PKCS1`), MD5 (Crypto); endpoints/headers/keys **1:1**
  (`com.microtech.aidexx,1.15.1`, `X-Forwarded-For` random-CN-IP,
  `encryption: enabled`, `X-Key-version: v2`); throttle/random-IP-логика —
  1:1 |
| `protocol/{AiDexOpcodes, AiDexCommandBuilder, AiDexParser}` +
  `data/{DataClasses, HistoryMerge}` | 1:1 (u16LE, offsets, CRC16,
  sentinels, 0x10/0x21/0x25/0x20/DP-chunk layout'ы — §12) |
| `native/ble/AiDexBleManager` (7492 lines) | CoreBluetooth: `CBUUID`
  `0x181F`/`0xF001`/`0xF002`/`0xF003`, CCCD (`setNotifyValue`); **MTU**:
  iOS-а его нет — убрать `MTU_SETTLE_BEFORE_CCCD_MS`/
  `MTU_CALLBACK_FALLBACK_MS` (логика ordering watchdog'ов и queue —
  1:1, константы — таблица §11); **bondState**: iOS-а такого нет —
  заменить на «first-connect / re-activated» flag (затягивается в
  `shouldRefreshLiveCccdsAfterKeyExchange`,
  `shouldReadSessionCharacteristicsBeforeFirstLive`,
  `decidePairKeyStartAction`) |
| `ble/{AiDexStreamingPolicy, AiDexHistoryPolicy, AiDexReconnect,
   AiDexRuntimePolicy}` | 1:1 (pure) |
| `protocol/{AiDexDefaultParamProvisioning, AiDexDpCatalogProvider,
   AiDexOfficialDpCatalogSnapshot}` + `AiDexWearProfile` | JSON snapshot
  (один и тот же) + JSON import (Application Support); `catalogWearDays`
  (uint32 LE byte 4, 86_400 check) |
| `adaptive2/*` (2 865 lines) | **1:1, не re-derive** (тюнинг на real-data;
  1.2 mmol/min ramp — «67%»); float/double-семантику сохранить;
  persistence — byte-compatible (CRC32) **или** Codable + version
  (тогда restore переписать — snapshot-совместимость теряется) |
| `AiDexTemperatureStore` / `AiDexSampleJournal` /
  `AiDexSourceJournalBackup` / `AiDexRetainedCalibration` | 1:1 (файлы
  Application Support вместо `filesDir` Android) |
| `AiDexScanReceiver` / `AiDexNativeFactory` /
  `AiDexManagedSensorIdentityAdapter` | `CBCentralManager` / реплейс native
  GATT (ReXdripswift уже имеет native-BLE stack) |
| `AiDexAlgorithmSelection` / `AiDexAlgorithmController` / `AiDexAlgorithmRuntime`
   / `AiDexAlgorithmReferences` | 1:1 (STOCK/ADAPTIVE_V2/ADAPTIVE_V2_CALIBRATED,
  persist id 0/8/9) |

**Дизайн-решения перед портом (решить заранее, не во время):**
- **MTU** — убрать (iOS-а нет), но сохранить ordering (no CCCD-write
  pending MTU) — на iOS MTU exchange **завершён** до GATT discovery, так
  что guard не нужен; проверить, что CCCD-write не ложится на MTU.
- **bondState** — заменить на свой флаг (нет iOS-bond); проверить все
  decision'ы, где `bondState` читается.
- **Keychain vs prefs+recovery** — backup strategy: file (Application
  Support) + `AiDexPairKeyBackup` (magic `JUGGLUCONG_AIDEX_PAIR_KEY`,
  version 1) — 1:1.
- **X-Forwarded-For** — vendor honors'ит; на iOS URLSession header
  settable — проверить, что он доходит (и что vendor его
  обрабатывает как на Android).
- **RSA-1024** — SecKey (`.PKCS1`); APP_SECRET + RSA-ключи — 1:1 из
  `AiDexCnProtocol` (не логировать).
- **broadcast-only** — `CBCentralManager` scan (match-по address/name,
  parse payload из advertisement); `parseBroadcastPayload` — §23,
  расшарить перед портом.

**Test vectors (готовые, из JugglucoNG-тестов):**
- SerialCrypto: `2222267V4E` → secret/IV (см. выше).
- Parser: 17B frame (byte[0] opcode, timeOffsetMinutes u16LE[4..5],
  glucosePacked u16LE[6..7] & 0x03FF, i1/i2 u16LE/100, CRC
  u16LE[15..16]); 1023 sentinel; raw/brief history entry'ы.
- Official DP snapshot (JSON, golden; import-override'ит).
- 1.2 mmol/min ramp (AdaptiveV2 — regression test).
- CN-облак: RSA-конверт + MD5 sign (unit-test на plain JSON).

**Порядок порта (рекоменд.):**
1. `crypto` (AES-CFB128, CRC, MD5, SerialCrypto) — **с test vector'а**
   (если secret/IV не match'ит — всё остальное не заработает).
2. `protocol` (Opcodes, CommandBuilder, Parser, KeyExchange, Parser —
   layout'ы §12, §4).
3. `AdaptiveV2` (2 865 строк) — **1:1**, persistence-форматы;
   **запускать раньше**, t.k. долгий (не bottleneck по времени, но
   математически сложный).
4. `ble` (BleManager) — CoreBluetooth-адаптер, MTU/bondState убрать,
   все константы/timing'ы (§11 таблица) + queue/watchdog'ы +
   startup-контрол (0x35→0x34→COMPLETE).
5. Policies (Streaming/History/Reconnect/Runtime) — 1:1 (pure).
6. CN-облак (CnCloudClient + Protocol + KeyManagementScreen-эквивалент).
7. Stores (Temperature, SampleJournal, SourceBackup, RetainedCalibration,
   ProvisioningStore, PairingMaterialFile, DpCatalog).
8. UI (setup-flow, key-management, display modes).

**Checklist (проверить на реальном сенсоре на каждом шаге):**
- [ ] F001 challenge → PAIR key (16B) — match'ит с Android HCI-трейсом.
- [ ] BOND (17B) → sessionKey (AES-CFB128) — match'ит.
- [ ] 0x10 → StartupDeviceInfo (fw/hw versions, wearDays, modelName).
- [ ] 0x20 SET_NEW_SENSOR (activation datetime) — ACK.
- [ ] 0x11 (sample 7B: offset/trend/glucose 10-bit) + F003 live (17B) —
  парсит.
- [ ] History 0x22/0x23/0x24 — парсит (calibrated brie raw).
- [ ] 0x25/0x26/0x27 calib — roundtrip.
- [ ] DP 0x30/0x31 — chunks, guard-apply.
- [ ] Key-exchange timeout (35 s) — не зависает.
- [ ] Reconnect: 1st attempt 2.5 s, 2nd 5 s, competing 20 s — match'ит
  Android-ladder'у.
- [ ] AdaptiveV2: FACTORY_ASSISTED + REFERENCE_ONLY — snapshot/restore
  roundtrip (CRC32 match).
- [ ] CN-облак: login + getSnConfig (X-Forwarded-For) — material
  (16+16B) match'ит Android-ключи.
- [ ] Broadcast-only: scan → payload → sample — парсит.
- [ ] Wear-profile: `catalogWearDays` — 15/10/8/7/14/16.
- [ ] 0xF2 DELETE_BOND → UNPAIR; PAIR-ключ clear (Keychain).
