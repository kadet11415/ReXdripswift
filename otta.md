# Ottai (M8 / Syai) CGM — полный протокол

Источник: `/Volumes/Kakao/xdrip-plus` — `xDrip/BluetoothTransmitter/CGM/Ottai/`
(состояние на 17.11.2026). Документ собран из исходников xdrip-plus и служит
эталоном для переноса недостающих правок в ReXdripswift
(ветка `7.2.1-aidex+lumifix+ottaifix`, файлы от 16.11.2026).

## 1. Архитектура

| Файл | Роль |
|---|---|
| `CGMOttaiTransmitter.swift` | BLE-транслимиттер: GATT, аутентификация, live-поток, история, активация, lifecycle |
| `Core/OttaiConstants.swift` | BLE-UUID, облачные адреса, lifetime, warmup, ID-хелперы |
| `Core/OttaiBleAuth.swift` | Auth V2: secp256r1 ECDH, SHA-256 подписи, сессионный ключ |
| `Core/OttaiCrypto.swift` | AES-ECB: облачные поля (keyA/method/coefficient) и BLE-payload |
| `Core/OttaiParser.swift` | дешифрованный пакет → 12-байтовые записи |
| `Core/OttaiFormula.swift` | РПН-формула глюкозы |
| `Core/OttaiOutputFilter.swift` | отбраковка невозможных значений и спайков |
| `Core/OttaiCloudClient.swift` | облачный API: CN / Global / Syai |
| `Core/OttaiGlobalContract.swift` | идентичность Global-телефона (legacy + новая) |
| `Core/OttaiSyaiClient.swift` | защищённый канал Syai (P-256 ECDH + HKDF + AES-GCM) |
| `Core/OttaiNetSecurity.swift` | secure-шлюз Global |
| `Core/OttaiV3BootstrapPolicy.swift` | политика setup/активации V3 |
| `Core/OttaiCloudUploader.swift` | загрузка замеров в облако Syai (только xDrip) |
| `Core/OttaiRegistry.swift` | персистентность: UserDefaults, материалы, checkpoint'и |
| `Core/OttaiNFCWake.swift` | пробуждение RF-полем NFC (CN/Syai) |
| `Core/OttaiSecureHTTP.swift` | обёртка HTTP-запросов |
| `Core/OttaiMethodDefaults.swift` | дефолтные method/коэффициенты |
| `Core/OttaiLoginFlow.swift` | оркестрация логина |
| `Core/OttaiAccountSensors.swift` | мульти-сенсорный учёт аккаунта |
| `Core/OttaiRegionalTransport.swift` | региональный транспорт (CN-IP и т.п.) |
| `Core/OttaiPhoneNumber.swift` | нормализация телефонного номера |

## 2. Идентификация сенсора

- Канонический cloud-ID: 12 hex-символов, заглавные, без двоеточий
  (`canonicalSensorId`). Это же ID идёт в BLE-логине и в облаке.
- BLE-адрес = тот же MAC, но с двоеточиями (`macWithColons`);
  `normalizeBleAddress` принимает 12-hex-plain только если явно сказано.
- QR на упаковке — GS1-код; ID сенсора это поле (21) serial number,
  НЕ (01) product number. Алгоритм выбора (`extractMacFromQr`):
  MAC с двоеточиями побеждает сразу; иначе среди всех 12-hex-прогонов
  побеждает лучший score: сразу после «21» (+8), содержит A–F (+4),
  стоит изолированно (+2).
- CN-облако отвечает только на запросы «из Китая»:
  `X-Forwarded-For: 114.114.114.114` (`cnForwardIp`).
- Cloud-«mac» не всегда равен BLE-адресу сенсора.
- `looksLikeMac`, `matchesCanonicalOrKnownNativeAlias` — проверки
  идентичности (case-insensitive сравнение канонических форм).

## 3. Карта GATT

Сервисы:

| UUID | Назначение |
|---|---|
| `0000180a-…` (DeviceInfo) | `00002a28` SW-версия, `00002a2b` текущее время |
| `0000181f-…` (CGM) | `00002aa7` live-глюкоза (notify) |
| `e06e1d43-1319-4ebf-94b0-5b0e5313b1f4` (Auth) | аутентификация |

Характеристики Auth-сервиса:

| UUID | Чт/Зт |
|---|---|
| `86805092-…` deviceParam | read |
| `1756ef6e-…` appParam | write |
| `785022c6-…` sign | read/write |

Характеристики CGM:

| UUID | Назначение |
|---|---|
| `d78d0706-…` command | статус/активация |
| `b8fd9848-…` maxActiveTime | lifetime (read/write) |
| `cb627922-…` cgmInfoNotify | notify |
| `ccecb015-…` historyRequest | write (запрос окна истории) |
| `69e4f45f-…` glucoseHistory | read |
| `6aa799b6-…` destructive | write (окончание сенсора) |

Команда активации `activateCmd = 0x03`: дополняется нулями до 16 байт,
шифруется сессионным ключом и пишется в `command`.

## 4. Аутентификация BLE — Auth V2 (локальная, ключи из облака)

Ключи: облако отдаёт `keyA` — 192 hex-символа = 6 ключей по 16 байт
(`authKeyCount = 6`, `authKeyBytes = 16`).

Форматы:
- `deviceParam` (read, ≥68 байт): `index(1) ‖ time(4) ‖ pubX(32) ‖ pubY(32)`
- `appParam` (write): `index(1) ‖ time3(3) ‖ appPubX(32) ‖ appPubY(32)`
- `time3`: bytes сенсора читаются big-endian, +1, берутся биты 24..8 (3 байта)
- подпись: `SHA256(authKey[i] ‖ mac ‖ pubX ‖ pubY ‖ time3)` (32 байта)

Сессионный ключ: ECDH secp256r1 (приватный ключ приложения ‖ публичный
сенсора) → общий X (32 байта, ведущие нули сохраняются) → hex → выбор
символов: старт позиция 2, шаги +1, +3, +1, +3, … (позиции 2,3,6,7,10,11,…)
→ нужен результат ≥32 hex-символа (= 16 байт, AES-128). Hex-строка и есть
`sessionKeyHex` (используется через `hexToBytesStrict`).

Порядок (`handleAuthSign` / `writeAppParam` / `handleWriteAck`):
1. read `deviceParam` → index, time, devPubX, devPubY.
2. read `sign` (32) → проверка
   `SHA256(key[index] ‖ mac ‖ devPubX ‖ devPubY ‖ time3)`.
   Результат только логируется (`lastVerifyFailed`); но если есть
   preparation-checkpoint и verify упал → `rotateAwayFromWrongSensor`
   (защита от физически неверного сенсора).
3. write `appParam`: случайный index 0..5, `time3` из device-time,
   свежая P-256 пара (`appKeyPair`).
4. write `sign`: `SHA256(key[appIndex] ‖ mac ‖ appPubX ‖ appPubY ‖ time3)`.
5. ECDH → `sessionKeyHex`; пусто → `recoverAndReconnect`.
6. `phase = .streaming`, читается `command`.

Против неверного сенсора: `rejectedPeripheralIdentifiers`,
`wrongSensorStrikes`, checkpoint-гейты.

## 5. V3 server-assisted auth (новый сенсор, локальных ключей нет)

1. read `deviceParam` + `sign` (флаги: 68/32 байта, flag — 32 hex-символа).
2. `POST cgmAuth/verify { mac, authDev, authFlag }`.
3. Ответ `V3AuthMaterial { authHost, authFlag }` → write `authHost` в
   appParam, `authFlag` в sign.
4. Ошибка `DEVICE_AUTH_SIGN_ERROR`: счётчик → `.retryConnection` /
   `.scanNextSensor` (запрос активации сохраняется, следующий сенсор) / `.stop`.
5. После записи: legacy Syai → `readServerFirmware`; иначе пауза 2.5 c →
   `requestPreparationRediscovery`.
Пустой challenge (все нули) → `recoverAndReconnect`.

## 6. Live-данные и записи

- notify на `charGlucoseLive` → AES-ECB-128 расшифровка
  (`sessionKeyHex`, без padding); если длина чётная и последние 8 байт
  все нули — эти 8 байт отбрасываются (`trimTrailingZeroBlock`).
- Пакет: заголовок 8 байт: `[0..3]` status (не используется),
  `[4..5]` dataNo первой записи (LE), `[6..7]` marker/count;
  далее записи по 8 или 9 байт.
- Размер записи (`chooseRecordSize`): сначала «чистые» данные
  (`vendorValidCount`: current ≥ 1000 и temp ≤ 45; минимум 3 записи,
  разрыв ≥ 2, и этот размер объясняет большинство записей) →
  потом `learned` (запомненный) → потом прошивка
  (E1.2.3 / V1.7 = 9 байт; V1.5 = 8) → иначе evidence 9 vs 8.
- 9-байтовые записи (V1.7) перекладываются в 12-байтовый вид:
  voltage = b6, runtime = dataNo*60 (16-битный счётчик оборачивается),
  current = src[0..1] LE, temp = src[7..8] LE; нулевые записи пропускаются.
- 12-байтовая запись: `{00,00} ‖ dataNo(2,LE) ‖ 8 байт`:
  - `[2..3]` dataNo (LE)
  - `[4]` voltage
  - `[5..7]` runtime = `(b5<<16) | (b7<<8) | b6`
    (такой перекрёстный порядок — правильный)
  - `[8..9]` raw current (LE)
  - `[10..11]` temperature*100 (LE) → /100.0
- Sanity (`isRecordSane`): `dataNo != 65535`; при `dataNo >= 60`
  `|dataNo − runtime/60| ≤ 120`.
- Live-режим использует только ПОСЛЕДНЮЮ запись; история — все.
- `monitorTimeMs = activeTimeMs + runtimeSec*1000`.

## 7. Формула глюкозы (`OttaiFormula`)

- РПН (обратная польская нотация). Токены: операторы, числа, имена.
- Имена подставляются ДО вычисления:
  - `C<i>` → коэффициент i
  - `V<i>` → переменная i
  - `B<i>` → байт i 12-байтовой записи (signed Int8)
  - `R<i>` → результат предыдущей группы
- Переменные `V`: `[rawCurrent, temperature, runtimeSec, dataNo, voltage]`.
- `C`: коэффициенты из облака (CSV). `B`: 12 байт записи.
- Операторы: `AD`(+), `SB`(−), `ML`(*), `DV`(/), `NG`(унар.), `AB`(|x|),
  `SQ`(√), `PW`(x^y), `BW`, `BE`, `GT`/`GE`/`LT`/`LE` (трёхместные),
  `RD`, `LN`(ln), `MX`(max), `MI`(min), `SN`/`CS`/`TN` (sin/cos/tan),
  `AS`/`AC`/`AT` (asin/acos/atan), `BA`(&), `BO`(|), `BN`(~), `BX`(^), `MD`.
- Несколько групп: первая считается, её результат доступен как `R0` и т.д.
- Пустой method → 0.0. 0.0 = слишком низко/некорректно.
- Вызов: `OttaiFormula.evaluate(method, coefficients, v, recordBytes)`.

## 8. Выходной фильтр (`OttaiOutputFilter`)

Парсер и формула не фильтруют; здесь отбрасываются невозможные значения
и одиночные спайки.
- `hardRejectReason(record:mmol:)`: mmol non-finite / ≤0 / > 40.0;
  temp non-finite / > 45.0 / < 15.0 → reject.
- `isOneMinuteRawExcursion`: скачок за 1 минуту ≥ 1.5 mmol И
  относительный скачок raw ≥ 0.18 → шум.
- `isMisframedFrame`: кадр из ≥8 записей, где большинство hard-reject
  и более половины temp невозможны (<0 или >60) → reject весь кадр.
- Полага `raw < 1000` НЕТ: такие записи пропускаются и показываются как
  LOW, чтобы слабый сенсор не выглядел как мёртвое соединение.
- Базлайн для spike-фильтра хранится в Registry
  (`continuityBaseline`) и переживает рестарт.

## 9. Активация и lifetime

- Байт command — истинное состояние: `0..2` = не активирован,
  `3` = streaming, `≥4` = сенсор окончен.
- `shouldStartActivation`: явный запрос пользователя +
  `commandNeedsActivation` (0..2). Активацию нельзя отменить —
  поэтому она только по явному запросу.
- Lifetime: `defaultActiveExpireMs = 15` сут; `retain = 172_800_000` ms;
  sanitize: принимать только 10..45 сут (иначе 0).
- `extendedLifetimeDays = 30` — самый длинный запрошиваемый при активации.
- `activationMaxActiveCandidatesMs`: 30,29,…,15 сут (шаг 1 сут) +
  `min(cloud, extended)`; дубликаты удаляются, порядок сохраняется.
- `expectedLifetimeMs`: accepted → cloud → default.
- Запись `maxActiveTime` ретраится (`retryMaxActiveTime`); сбой →
  `failLifetimeOperation`.
- `LifetimeEvidence`: `legacy` / `writeAcknowledged` / `sensorReadback`.
- Checkpoint до необратимой команды: только нон-секрет identity +
  timestamps (никогда не признак успеха активации).
- Warmup: `3600` c (1 ч) — замеры расшифровываются, но не используются;
  `isWithinWarmup(activationStartMs, sampleMs, preheatPeriodMs)`.
  60-минутный warmup производителя никогда не укорачивать.
- `defaultReadingIntervalMinutes = 1`.

## 10. Облако

### 10.1 Регионы и адреса

| Регион | apiBase |
|---|---|
| CN (телефон + SMS) | `https://api.ottai.com` |
| Global (username + пароль) | `https://seas.ottai.com` |
| Syai (global) | `https://api.syai.com` (legacy `https://ru.syai.com`) |

Web: `https://www.ottai.com/api/cgm/web`, `https://www.syai.com/api/cgm/web`.
Префикс `/cgm/app/server`.

Эндпоинты:
- `user/apiToken`, `user/smsCode`, `user/smsLogin`, `user/accountLogin`, `user/logout`
- `device/validateDeviceByMacV2`, `device/validateDeviceByMacV3`
- `deviceBind/composite/bind`, `deviceBind/composite/bindV3`
- `cgmAuth/verify`
- `deviceBind/unBindDevice`, `deviceBind/getBindDevice`, `deviceBind/list`

### 10.2 Логин
- CN: телефон + SMS (`smsCode` → `smsLogin` → `accountLogin`),
  `X-Forwarded-For: cnForwardIp`, подпись MD5.
- Global: username + пароль. Тело: `uuid`, `source=5`, `encryptInfo`,
  `apiToken`, `signature`; если в username нет «@» → `type=3`/`loginType=3`
  + `username`. Эндпоинт: `contains("@") ? loginURL : usernameLoginURL`.
- Syai: install-device-id вида `Syai Tag:i:n:<uuid>` (v3 UUID).
- Результат логина: `apiToken` + `glucoseSecretKey` (+ `userId`).
- Профили сессии: `WATCH`, `CN_PHONE`, `GLOBAL_PHONE` (legacy,
  ottai-seas), `GLOBAL_PHONE_20261115` (новая, ottai/com.ottai.seas).

### 10.3 Материалы сенсора: keyA / method / coefficient
- На каждый сенсор облако шлёт три зашифрованных поля:
  - `keyA` — 6×16B BLE-ключи (192 hex)
  - `method` — формула глюкозы
  - `coefficient` — числа для формулы
- Ключ поля: `fieldKey = glucoseSecretKey + last10(<time>) + last6(<mac>)`.
  - `keyA` → time = `produceTime`
  - `method` → time = `methodUpdateTime`
  - `coefficient` → time = `coeffUpdateTime`
- Шифр: AES-ECB, PKCS7, без IV. base64.
- `keyA` ровно 192 hex → `parseAuthKeys` → 6×16B. Иначе nil.
- Дефолт method: `OttaiMethodDefaults.resolve(method, coefficient)` —
  пустой method разрешается по коэффициенту.
- `hasAll` = keyA непустой + method непустой + `activeTimeMs > 0`.

### 10.4 validate / bind / unbind / cgmAuth
- `validate` V2 (CN legacy) / V3 (`globalPhone` →
  `POST validateDeviceByMacV3`, идентичность как у нового телефона) →
  keyA, method, coefficient, `activeExpireMs`, прошивка, `requiresV3Bind`.
- `bind`: legacy M8 (`epBind`) / V3 (`epBindV3`).
- `bindRejected`: только ЯВНОЕ отказ (`isExplicitBindRefusal`:
  `value == nil` И `code != nil`), а не просто пустой ответ.
- `AppUser_AlreadyBinding`: на аккаунт уже висит другой сенсор →
  `currentGlobalBinding` + `releasePreviousGlobalBinding`
  (с явным подтверждением).
- `cgmAuth/verify`: V3-аутентификация (см. §5).
- `unbind`: CN `unbindType = 0`; Global
  `globalRetiredSensorUnbindType = 13`.
- `getBindDevice`: текущая привязка (до release).
- `deviceBind/list`: `items: null` = пустой список, а не ошибка.
- Защита сессии: `requireCurrentGlobalSession()` проверяется в
  validateForSetup, bind, cgmAuthVerify, bindDeviceResponse,
  accountSensors, unbind, fetchAndSaveMaterials.

### 10.5 Идентичность Global (`OttaiGlobalContract`)
| | Legacy (1.38) | Новая (20261115) |
|---|---|---|
| appName | `ottai-seas` | `ottai` (legacyAppName = `ottai-seas`) |
| deviceIDPrefix | `ottai-seas:a:g:` | `ottai:a:g:`
  (legacyDeviceIDPrefix = `ottai-seas:a:g:`) |
| identity | Android 1.38.0 / 261721 | Android 1.1.0 / 244301
  «Android_Watch_Ottai_Arc» |
| login URL | `variousLogin` | `thirdLoginByPassword` +
  `variousLogin` (username) |
- Старый токен хранит свою исходную идентичность, пока не будет
  закоммичен новый логин (`loadLegacyGlobalHeaderDeviceId` /
  `loadOrCreateGlobalHeaderDeviceId`). Старые сессии 1.38 НИКОГДА не
  переименовывать.
- `checkedSensor` / `authInfoRequest` используют legacy-идентичность.

### 10.6 Защищённые каналы
- Syai: P-256 ECDH + HKDF + AES-GCM (`OttaiSyaiClient`).
- Global: secure-шлюз (`OttaiNetSecurity`).

## 11. Персистентность (UserDefaults)

Аккаунт: `ottai_access_token`, `ottai_refresh_token`,
`ottai_syai_install_device_id`, `ottai_glucose_secret_key`, `ottai_user_id`,
`ottai_account_login`, `ottai_api_base`, `ottai_session_profile`,
`ottai_session_generation`, `ottai_self_device_id`,
`ottai_cn_common_device_id`, `ottai_global_common_device_id`,
`ottai_global_phone_device_id`, `ottai_sensors`.

Пер-сенсор (префикс + id): `ottai_keya_`, `ottai_method_`, `ottai_coeff_`,
`ottai_active_time_`, `ottai_provisional_active_time_`, `ottai_active_expire_`,
`ottai_accepted_max_active_`, `ottai_lifetime_evidence_`,
`ottai_preheat_period_`, `ottai_grace_period_`,
`ottai_factory_calibration_k_`, `ottai_factory_calibration_b_`,
`ottai_retain_time_`, `ottai_device_version_`, `ottai_last_datano_`,
`ottai_delivered_datano_`, `ottai_record_size_`,
`ottai_continuity_baseline_`, `ottai_device_id_`, `ottai_act_tried_`,
`ottai_activation_checkpoint_`, `ottai_activation_status_`,
`ottai_activation_started_`, `ottai_sensor_status_`,
`ottai_v3_bootstrap_pending_`, `ottai_pending_bind_`,
`ottai_legacy_preparation_`.

Загрузка в Syai: `ottai_cloud_upload_enabled`, `ottai_cloud_upload_status`,
`ottai_draft_sensors`.

- `normalizeOttaiActiveTimeMs`: старый cloud отдаёт ms, CN-V3-bind —
  секунды; храним всегда ms (значение 1..9_999_999_999 → *1000).
- `removeSensor`: удаляет все пер-сенсор ключи, КРОМЕ
  `acceptedMaxActive` (намеренно, как в Kotlin).
- `commitRefreshedSyaiSession`: коммитит Syai-refresh только пока
  исходный аккаунт владеет сессией.
- `beginGlobalLogin`: старт Global-логина (новая generation,
  `apiBase == apiBaseGlobal`).
- `commitGlobalLogin`: коммитит `globalPhone`-профиль, кладёт
  `glucoseSecretKey`, `userId`, `accessToken`, новый generation.

## 12. V3 bootstrap / setup
- `V3CredentialBootstrapPending`: флаг, пока материалы не сохранены.
- `pendingBind`: время старта server-активированного сенсора, ещё не
  привязанного → пока он стоит, сенсор НЕ активируется повторно.
- Checkpoint: account-bound, сохраняется до необратимой команды.
  `OttaiActivationAttempt.isValid`, sensorID должны совпадать.
- `saveMaterials`: пустой coefficient → берётся старый; method разрешается
  дефолтом; `activeExpire` санитизируется.
- `prepareNew` — отдельный шаг `OttaiV3BootstrapPolicy` для нового
  Global-сенсора (`newGlobalSensor = loadApiBase() == apiBaseGlobal`).
- Гейт: bind ПЕРЕД записью factory-параметров.

## 13. NFC wake (`OttaiNFCWake`)
- Только CN (`apiBase`) и Syai; Global НЕ требуется (использует Bluetooth).
- Пассивное RF-поле: НЕ подключается к тегу, НЕ читает/пишет
  application-данные.
- `NFCTagReaderSession(.iso14443)`: события `readerReady`, `tagDetected`,
  `invalidated`.
- Исходы: `tagObserved` / `cancelled` / `timedOut` / `ownerChanged` /
  `notRequired` / `busy` / `unavailable` / `failed`.
- `tagObserved`: «тег обнаружен, но идентичность и пробуждение НЕ
  подтверждены» — это наблюдение, а не доказательство.
- Включается по `OttaiNFCWakeEnabled` в Info.plist (signing-возможность).
- Таймаут 60 c; уход на background → `cancelled`.
- `alertMessage`: «Hold the top of iPhone near the sensor… This does not
  activate the sensor.»

## 14. Загрузка в Syai (`OttaiCloudUploader`)
- Только xDrip: загрузка замеров в облако Syai.
- Управление: `ottai_cloud_upload_enabled` / `ottai_cloud_upload_status`.
- Черновики сенсоров: `ottai_draft_sensors`.

## 15. Ключевые константы
- `tag = "Ottai"`, `defaultDisplayName = "Ottai CGM"`.
- `activateCmd = 0x03`.
- `cnForwardIp = 114.114.114.114`.
- `defaultRatedLifetimeDays = 15`; `defaultRetainTimeMs = 172_800_000`.
- `extendedLifetimeDays = 30`; `minActiveExpireMs = 10` сут;
  `maxActiveExpireMs = 45` сут.
- `defaultReadingIntervalMinutes = 1`; `defaultWarmupSeconds = 3600`;
  `defaultPreheatPeriodMs = 3_600_000`; `warmupSuppressMs = 3_600_000`.
- `headerSize = 8`; `bleRecordSize = 8`; `bleRecordSizeE12 = 9`;
  `parserRecordSize = 12`; `invalidDataNo = 65535`.
- `authKeyCount = 6`; `authKeyBytes = 16`; `authKeyHexLen = 192`.
- `fieldLen` (P-256) = 32.
