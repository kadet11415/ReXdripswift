//
//  OttaiDevicePickerView.swift
//  xdrip
//

import SwiftUI

/// Modal sheet that lets the user pick one Ottai sensor from the scan results.
struct OttaiDevicePickerView: View {
    let devices: [DiscoveredOttaiSensor]
    let onSelect: (DiscoveredOttaiSensor) -> Void
    let onCancel: () -> Void

    @Environment(\.dismiss) private var dismiss

    private var sortedDevices: [DiscoveredOttaiSensor] {
        devices.sorted { $0.rssi > $1.rssi }
    }

    var body: some View {
        NavigationView {
            List {
                ForEach(sortedDevices, id: \.peripheral.identifier) { device in
                    Button {
                        dismiss()
                        onSelect(device)
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(device.name)
                                    .foregroundColor(.primary)
                                Text(device.peripheral.identifier.uuidString)
                                    .font(.caption2)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            HStack(spacing: 4) {
                                Image(systemName: rssiSymbol(rssi: device.rssi))
                                    .font(.caption)
                                Text("\(device.rssi) dBm")
                                    .font(.caption.monospacedDigit())
                            }
                            .foregroundColor(rssiColor(rssi: device.rssi))
                        }
                    }
                }
            }
            .navigationTitle("Select Ottai Sensor")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                        onCancel()
                    }
                }
            }
        }
    }

    private func rssiSymbol(rssi: Int) -> String {
        rssi > -65 ? "wifi" : "wifi.slash"
    }

    private func rssiColor(rssi: Int) -> Color {
        rssi > -65 ? .green : (rssi > -80 ? .yellow : .red)
    }
}
