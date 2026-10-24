//
//  OttaiScanOnly.swift
//  xdrip
//
//  Scan-only mode for Ottai/Syai: collect nearby sensors without auto-connecting.
//  Mirrors the Aidex pattern: a private scanner with its own CBCentralManager,
//  filtered by name prefix, with a 10 s timeout. The user picks a sensor from
//  the list before any connection is attempted.
//

import CoreBluetooth
import Foundation
import os

struct DiscoveredOttaiSensor {
    let peripheral: CBPeripheral
    let name: String
    let rssi: Int
    let advertisementData: [String: Any]
}

private final class OttaiDeviceScanner: NSObject, CBCentralManagerDelegate {

    private static let log = OSLog(subsystem: ConstantsLog.subSystem, category: ConstantsLog.categoryCGMOttai)

    /// Known name prefixes for Ottai / Syai BLE sensors (case-insensitive match).
    static let knownNamePrefixes = ["Ottai", "OTTAI", "Syai", "SYAI"]

    private let deviceName: String
    private let completion: (([DiscoveredOttaiSensor]) -> Void)
    private var centralManager: CBCentralManager?
    private var discovered: [UUID: DiscoveredOttaiSensor] = [:]
    private var timeoutWork: DispatchWorkItem?
    private var queue: DispatchQueue?

    init(deviceName: String, completion: @escaping ([DiscoveredOttaiSensor]) -> Void) {
        self.deviceName = deviceName
        self.completion = completion
        super.init()
    }

    func start(timeout: DispatchWorkItem, queue: DispatchQueue) {
        self.queue = queue
        self.timeoutWork = timeout
        os_log("OttaiScanner: creating CBCentralManager on queue=%{public}@ log", Self.log, queue.label)
        centralManager = CBCentralManager(delegate: self, queue: queue,
                                          options: [CBCentralManagerOptionShowPowerAlertKey: false])
        queue.asyncAfter(deadline: .now() + .seconds(10), execute: timeout)
    }

    func stop() {
        os_log("OttaiScanner: stop — discovered %{public}d", Self.log, discovered.count)
        centralManager?.stopScan()
        centralManager?.delegate = nil
        centralManager = nil
        timeoutWork?.cancel()
        timeoutWork = nil

        let devices = discovered.values.sorted { $0.rssi > $1.rssi }
        completion(devices)
    }

    // CBCentralManagerDelegate

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        os_log("OttaiScanner: centralManager state=%{public}d", Self.log, central.state.rawValue)
        if central.state == .poweredOn {
            // Ottai sensors advertise the 0x181F blood glucose service. Scanning
            // without a service filter would also catch other BLE types; the Aidex
            // driver uses no filter, but for Ottai we rely on the 0x181F BGM service
            // plus a name prefix check in didDiscover.
            central.scanForPeripherals(withServices: [CBUUID(string: "181F")],
                                       options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
        }
    }

    func centralManager(_ central: CBCentralManager,
                        didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any],
                        rssi RSSI: NSNumber) {
        let name = peripheral.name ?? advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? ""
        os_log("OttaiScanner: didDiscover name='%{public}@' rssi=%{public}@'", Self.log, name, RSSI)

        let isOttaiSensor = name.isEmpty ? false : Self.knownNamePrefixes.contains { prefix in
            name.range(of: prefix, options: .caseInsensitive) != nil
        }
        guard isOttaiSensor else { return }
        guard discovered[peripheral.identifier] == nil else { return }

        os_log("OttaiScanner: matched Ottai sensor: name='%{public}@' rssi=%{public}@'", Self.log, name, RSSI)
        let entry = DiscoveredOttaiSensor(
            peripheral: peripheral,
            name: name,
            rssi: RSSI.intValue,
            advertisementData: advertisementData
        )
        discovered[peripheral.identifier] = entry
    }
}

// MARK: - CGMOttaiTransmitter scan-only API

extension CGMOttaiTransmitter {

    /// Scan-only mode: collect all nearby Ottai sensors without connecting.
    func scanForDevices() {
        // Prevent duplicate scanners
        if objc_getAssociatedObject(self, &OttaiAssociatedKeys.scanner) != nil {
            trace("CGMOttai: scanForDevices skipped — scanner already running",
                  log: CGMOttaiTransmitter.staticLog,
                  category: ConstantsLog.categoryCGMOttai,
                  type: .info)
            return
        }
        trace("CGMOttai: scanForDevices called",
              log: CGMOttaiTransmitter.staticLog,
              category: ConstantsLog.categoryCGMOttai,
              type: .info)
        discoveredOttaiDevices = [:]
        ottaiScanTimeoutWork?.cancel()

        let queue = DispatchQueue(label: "ottai.scanonly.\(UUID().uuidString.prefix(8))", qos: .userInitiated)
        let scanner = OttaiDeviceScanner(deviceName: deviceName ?? "Ottai") { [weak self] devices in
            os_log("Ottai: scanner completion called, devices=%{public}d", CGMOttaiTransmitter.staticLog, devices.count)
            guard let self else {
                os_log("Ottai: scanner completion — self is nil, dropping results", CGMOttaiTransmitter.staticLog)
                return
            }
            objc_setAssociatedObject(self, &OttaiAssociatedKeys.scanner, nil, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
            self.ottaiScanTimeoutWork = nil
            self.discoveredOttaiDevices = Dictionary(uniqueKeysWithValues: devices.map { ($0.peripheral.identifier, $0) })
            os_log("Ottai: discoveredOttaiDevices populated, count=%{public}d", CGMOttaiTransmitter.staticLog, self.discoveredOttaiDevices.count)

            DispatchQueue.main.async {
                self.ottaiDidFinishScanning(devices: devices, from: self)
            }
        }

        objc_setAssociatedObject(self, &OttaiAssociatedKeys.scanner, scanner, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)

        let timeout = DispatchWorkItem { [weak scanner] in
            scanner?.stop()
        }
        ottaiScanTimeoutWork = timeout
        scanner.start(timeout: timeout, queue: queue)
        trace("Ottai: scanner.start() called", log: CGMOttaiTransmitter.staticLog, category: ConstantsLog.categoryCGMOttai, type: .info)
    }

    /// Connect to a specific Ottai device discovered during scan-only mode.
    func connectToDiscoveredDevice(_ discovered: DiscoveredOttaiSensor) {
        trace("CGMOttai: connectToDiscoveredDevice name=%{public}@ addr=%{public}@'",
              log: CGMOttaiTransmitter.staticLog,
              category: ConstantsLog.categoryCGMOttai,
              type: .info,
              discovered.name,
              discovered.peripheral.identifier.uuidString)

        ottaiScanTimeoutWork?.cancel()
        ottaiScanTimeoutWork = nil
        objc_setAssociatedObject(self, &OttaiAssociatedKeys.scanner, nil, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)

        // The Ottai driver uses its own BLE connection flow (workQueue).
        // For scan-only selection we need to route through the standard connect
        // path. Set deviceName and call self.connect() to trigger the base-class
        // flow; the discovered peripheral's identifier is available via
        // self.peripheral in didDiscover.
        deviceName = discovered.name
        deviceAddress = discovered.peripheral.identifier.uuidString
        stopScanning()
        connect()
    }

    /// Connect to a device selected by the user from scan results (by device address).
    func connectToDiscoveredDevice(withAddress address: String) {
        guard let device = discoveredOttaiDevices.values.first(where: {
            $0.peripheral.identifier.uuidString == address
        }) else {
            trace("CGMOttai: connectToDiscoveredDevice — address %{public}@ not found",
                  log: CGMOttaiTransmitter.staticLog,
                  category: ConstantsLog.categoryCGMOttai,
                  type: .error,
                  address)
            return
        }
        connectToDiscoveredDevice(device)
    }
}

// MARK: - associated object keys

private struct OttaiAssociatedKeys {
    static var scanner: UInt8 = 0
}

// MARK: - CGMOttaiTransmitter internal state (visible via extension)

extension CGMOttaiTransmitter {

    static let staticLog = OSLog(subsystem: ConstantsLog.subSystem, category: ConstantsLog.categoryCGMOttai)
}

// MARK: - Ottai scan completion callback

extension CGMOttaiTransmitter {

    /// Called when the scan-only mode completes (10 s timeout or user selection).
    /// Forwards events to the UI via the CGMTransmitterDelegate pattern.
    /// The actual presentation of the device list is handled by the UI layer
    /// listening to the .ottaiDidFinishScanning notification (see
    /// BluetoothPeripheralDetailState).
    func ottaiDidFinishScanning(devices: [DiscoveredOttaiSensor], from cGMOttaiTransmitter: CGMOttaiTransmitter) {
        DispatchQueue.main.async {
            NotificationCenter.default.post(
                name: .ottaiDidFinishScanning,
                object: nil,
                userInfo: [
                    "devices": devices,
                    "transmitter": cGMOttaiTransmitter
                ]
            )
        }
    }
}

extension Notification.Name {
    static let ottaiDidFinishScanning = Notification.Name("ottaiDidFinishScanning")
}
