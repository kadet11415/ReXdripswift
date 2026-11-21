# Список различий: ReXdripswift → xdrip-plus

Сравнено:
- эталон: `/Volumes/Kakao/xdrip-plus` (файлы от 17.11.2026)
- цель: `/Volumes/Kakao/ReXdripswift`, ветка `7.2.1-aidex+lumifix+ottaifix`
  (файлы от 16.11.2026)
- направление diff: строки `-` = есть в ReXdripswift (старое, к удалению),
  строки `+` = есть в xdrip-plus (правка, которую нужно перенести).

Итог: **6 файлов различаются** + 2 интеграционные области вне папки Ottai
+ 2 лишних файла только в ReXdripswift. 15 файлов в `Core/` побайтово
идентичны — их трогать не нужно.

## Идентичны (не трогать)

`Core/OttaiBleAuth`, `OttaiCloudUploader`, `OttaiConstants`, `OttaiCrypto`,
`OttaiFormula`, `OttaiLoginFlow`, `OttaiMethodDefaults`, `OttaiNFCWake`,
`OttaiNetSecurity`, `OttaiOutputFilter`, `OttaiParser`, `OttaiPhoneNumber`,
`OttaiRegionalTransport`, `OttaiSecureHTTP`, `OttaiSyaiClient`.

## 1. `Core/OttaiRegistry.swift`
- Профиль `globalPhone = "GLOBAL_PHONE"` → разведён на два:
  `globalPhoneLegacy = "GLOBAL_PHONE"` (старые сессии 1.38, ottai-seas,
  никогда не переименовывать) + `globalPhone = "GLOBAL_PHONE_20261115"`
  (текущая, ottai/com.ottai.seas).
- `loadOrCreateGlobalHeaderDeviceId`: ключ `globalCommonDeviceId` →
  новый `globalPhoneDeviceId` (+ проверка `validDeviceID`).
- Добавлен `loadLegacyGlobalHeaderDeviceId` — старый токен хранит свою
  исходную идентичность до нового логина (`globalCommonDeviceId`).
Зачем: разделение legacy/новой Global-идентичности.

## 2. `Core/OttaiGlobalContract.swift`
- `appName`: `ottai-seas` → `ottai` (+ `legacyAppName = "ottai-seas"`).
- `deviceIDPrefix`: `ottai-seas:a:g:` → `ottai:a:g:`
  (+ `legacyDeviceIDPrefix = "ottai-seas:a:g:"`).
- login URL: `variousLogin` → `thirdLoginByPassword`; добавлен
  `usernameLoginURL = variousLogin` (username без «@»).
- headers: Android 1.38.0/261721 → Android 1.1.0/244301
  «Android_Watch_Ottai_Arc»; старые headers вынесены в `legacyHeaders`.
- `passwordBody`: `[encryptInfo, apiToken, signature, type=2, phoneCode=""]`
  → `[uuid, source=5, encryptInfo, apiToken, signature]`; если в username
  нет «@» → `type=3`/`loginType=3` + `username`.
- Эндпоинт логина: всегда `loginURL` →
  `account.contains("@") ? loginURL : usernameLoginURL`.
- Добавлены `validDeviceID` / `validLegacyDeviceID` (две идентичности).
Зачем: Global-приложение сменило идентичность
(ottai-seas 1.38 → ottai 1.1.0 Android_Watch); legacy сохранён
для старых токенов.

## 3. `Core/OttaiCloudClient.swift` (самое крупное различие)
- Добавлен `isExplicitBindRefusal`: bindRejected только при ЯВНОМ отказе
  (`value == nil && code != nil`), а не просто на пустой ответ.
- Добавлен `requireCurrentGlobalSession()` — вызывается в
  validateForSetup, bind, cgmAuthVerify, bindDeviceResponse,
  accountSensors, unbind, fetchAndSaveMaterials (защита сессии).
- `isSignedIn`: теперь учитывает `globalPhone`.
- `validateForSetup` globalPhone: `checkedSensor` (M8 legacy) →
  `POST validateDeviceByMacV3` (идентичность нового телефона);
  `requiresV3Bind = device.keyA.isEmpty` (было всегда false).
- `bind()`: контракт `.globalM8` → `.v3`.
- `bindAfterServerActivation`: `.globalM8` → `.v3`.
- `unbind`: `unbindType = 0` → Global =
  `globalRetiredSensorUnbindType = 13`.
- `globalAuthInfoSign`: `md5Hex(seed + appName + …)` → `legacyAppName`
  (значения те же, переименование).
- Добавлен `prepareActivationMaterialsResult` /
  `prepareActivationMaterialsImpl` + колбэк `onBindRejected`.
- Добавлены `currentGlobalBinding` / `releasePreviousGlobalBinding`
  (unbind предыдущего сенсора с явным подтверждением).
- Добавлены `httpPutJsonResult` (PUT), новые requestStage-метки, текст
  ошибки gateway500.
- `bind()`: + `requireCurrentGlobalSession`.
Зачем: V3 для Global-телефона, защита сессии, явный bind-refusal,
развязка предыдущего сенсора.

## 4. `CGMOttaiTransmitter.swift`
- Удалены scan-only state-переменные (`discoveredOttaiDevices`,
  `ottaiScanTimeoutWork`) — scan-only режим отсутствует в xdrip-plus.
- Добавлен `preparationTestSend`.
- `fetch()`: возвращает `PreparationResult` (было `DeviceMaterials?`).
- Используется `prepareActivationMaterialsResult`
  (было `prepareActivationMaterials`).
- Проверка bindRejected: match + guard `confirmedStartMs == 0`.
Внимание: в ReXdripswift есть `Core/OttaiScanOnly.swift` — см. «Лишние файлы».

## 5. `Core/OttaiAccountSensors.swift`
- Строгий history-парсинг:
  `guard let data = try payload(body), let rows = (data["items"] ?? data["list"] ?? data["records"]) as? [[String: Any]] else { throw }`
  (было: `as? [[String: Any]] ?? []` → пустой список). Пустых rows теперь —
  ошибка, а не молчаливый пустой список.
- Мелкие текстовые правки.

## 6. `Core/OttaiV3BootstrapPolicy.swift`
- Новый шаг `.prepareNew` в `OttaiSetupStep`.
- `resolve()`: новый параметр `newGlobalSensor`.
- Текст шага: «Prepare new sensor» / «Get the settings for this sensor.»
  (`newGlobalSensor = loadApiBase() == apiBaseGlobal`).

## Интеграция вне папки Ottai (Ottai-составляющая)
- `BluetoothPeripheralManager.swift`: удалён scan-only режим
  (`if type == .OttaiType … { ottaiTransmitter.scanForDevices() }`
  и комментарий «use scan-only mode»).
- `BluetoothPeripheralDetailState.swift` (крупнейший интеграционный дифф):
  - удалены scan-only: `discoveredOttaiDevices`, `selectOttaiDevice`,
    `handleOttaiScanResults`, использование `OttaiDevicePickerView`;
  - добавлен action «Unlink previous cloud sensor»
    (`requestOttaiReleaseCurrentBinding`);
  - добавлен action «Restore already activated sensor»
    (`requestOttaiFetchMaterials`);
  - добавлен `newGlobalSensor: loadApiBase() == apiBaseGlobal`;
  - добавлен `case .prepareNew`.
- `BluetoothPeripheralDetailView.swift`: удалён показ
  `OttaiDevicePickerView`.
- `RootApplicationCoordinator.swift`: удалена строка
  `case .ottai: minimumWarmUpRequiredInMinutes =
   ConstantsMaster.minimumSensorWarmUpRequiredInMinutesOttai`
  (warmup ведёт сам драйвер).

## Не переносить: Sibionics
xdrip-plus содержит отдельный драйвер **Sibionics GS1 CN**. Эти строки в
интеграционных файлах НЕ относятся к Ottai и не перенеслись бы без
дровера Sibionics (его в ReXdripswift нет). Затронутые места
(игнорировать при порте Ottai):
`BluetoothPeripheralType.swift` (`SibionicsCNType`),
`CGMTransmitter.swift` / `CGMTransmitterDelegate.swift`
(`sibionicsCN`, `GS1Policy.warmup`), `BluetoothPeripheralManager.swift`,
`LoopManager.swift` (warmup: `ConstantsAidex.warmupMinutes`,
`GS1Policy.warmup`), `BgPostProcessingManager.swift`
(`enableGlucoseAdjustment/CurveAdjustment = false`), `AlertKind.swift`,
`TroubleshootingLog.swift`, `BLEPeripheral+CoreDataProperties.swift`,
`WidgetSharedUserDefaultsModel.swift`, `BluetoothPeripheralsViewModel.swift`,
`RootApplicationCoordinator.swift` (`configureGlucosePipeline`,
`synchronizeDetectedSensorStartDate`), и model-файлы
`xdrip personal v33/v34/v35.xcdatamodel`.
В `CGMTransmitter.swift` единственная «чистая» Ottai-правка — комментарий:
«Ottai sends glucose that is already calibrated like Libre.» удалён,
осталось «Start and change sensors through the guarded Ottai setup screen.»

## Лишние файлы только в ReXdripswift (в xdrip-plus их нет)
- `Core/OttaiScanOnly.swift` (227 строк) — scan-only режим. НЕ недостающая
  правка. При порте диффа `CGMOttaiTransmitter.swift` как есть
  state-переменные скана удалятся → файл окажется осиротленным
  (удалить либо адаптировать).
- `SwiftUIViews/BluetoothPeripherals/OttaiDevicePickerView.swift` (68 строк) —
  UI выбора устройства из скана. Тоже осиротлеет при порте.
- Aidex-файлы (не Ottai): `AidexPairKeyBackup`, `AidexPairKeyVault`,
  `AidexProvisioningStore`, `AidexRuntimePolicy`, `AidexWearProfile`, `CnCloud`.

## Лишь в xdrip-plus (для сведения)
- `Aidex/AidexReadingPolicy.swift`
- `Sibionics/` (целая папка), `SibionicsCN.swift`
- `xdrip personal v33/v34/v35.xcdatamodel`

## Порядок переноса (зависимости)
1. `OttaiRegistry` — профили `GLOBAL_PHONE`/`GLOBAL_PHONE_20261115`,
   новый ключ `globalPhoneDeviceId`, `loadLegacyGlobalHeaderDeviceId`.
2. `OttaiGlobalContract` — новая идентичность + legacy-поля.
3. `OttaiCloudClient` — V3 validate/bind, `requireCurrentGlobalSession`,
   `releasePreviousGlobalBinding`, `isExplicitBindRefusal`.
4. `CGMOttaiTransmitter` — `PreparationResult`, удаление scan-only state.
5. `OttaiV3BootstrapPolicy` — шаг `prepareNew`.
6. `OttaiAccountSensors` — строгий history-парсинг.
7. Интеграция: `BluetoothPeripheralManager` /
   `BluetoothPeripheralDetailState` / `BluetoothPeripheralDetailView`
   (удалить scan-only, добавить action'ы).

Решение по scan-only: xdrip-plus его убрал, у вас он есть. Если переносить
транслимиттер как есть — `OttaiScanOnly.swift` и
`OttaiDevicePickerView.swift` нужно удалить (или подогнать под новую
структуру).
