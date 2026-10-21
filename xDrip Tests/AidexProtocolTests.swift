import XCTest
@testable import xdrip

final class AidexProtocolTests: XCTestCase {
    func testStartupInfoFrameParsesOpcodePayloadAndCRC() {
        var frame = Data([0x10, 0x00, 0x00, 1, 2, 3, 14, 0, 0, 0x47, 0x58, 0x2D, 0x30, 0x31, 0, 0, 0])
        frame = CRC16.append(frame)

        let info = AidexParser.parseStartupDeviceInfoFrame(frame)

        XCTAssertEqual(info?.firmwareVersion, "1.2")
        XCTAssertEqual(info?.hardwareVersion, "3.14")
        XCTAssertEqual(info?.wearDays, 14)
        XCTAssertEqual(info?.modelName, "GX-01")
    }

    func testStartupInfoFrameRejectsInvalidCRCAndMalformedHeader() {
        var invalidCRC = CRC16.append(Data([0x10, 0x00, 0x00, 1, 2, 3, 14, 0, 0, 0x47, 0x58, 0x2D, 0x30, 0x31, 0, 0, 0]))
        invalidCRC[invalidCRC.count - 1] ^= 0x01
        XCTAssertNil(AidexParser.parseStartupDeviceInfoFrame(invalidCRC))

        let badHeader = CRC16.append(Data([0x10, 0x01, 0x00, 1, 2, 3, 14, 0, 0, 0x47, 0x58, 0x2D, 0x30, 0x31, 0, 0, 0]))
        XCTAssertNil(AidexParser.parseStartupDeviceInfoFrame(badHeader))
        XCTAssertNil(AidexParser.parseStartupDeviceInfoFrame(Data([0x10])))
    }

    func testLegacyStartTimeParserAcceptsValidAndAllZeroPayloads() {
        let valid = Data([0xE8, 0x07, 10, 21, 12, 30, 45, 0, 0])
        let parsed = AidexParser.parseLocalStartTimePayload(valid)
        XCTAssertEqual(parsed?.year, 2024)
        XCTAssertEqual(parsed?.month, 10)
        XCTAssertEqual(parsed?.day, 21)

        XCTAssertTrue(AidexParser.parseLocalStartTimePayload(Data(repeating: 0, count: 9))?.isAllZeros == true)
        XCTAssertNil(AidexParser.parseLocalStartTimePayload(Data([0xFF, 0xFF, 13, 32, 25, 61, 61])))
    }

    func testF003FrameClassificationAndCRCValidation() {
        var frame = Data(repeating: 0, count: AidexFrame.dataFrameLength)
        frame[0] = 0xA1
        frame[6] = 100
        let crc = CRC16.checksum(frame.prefix(15))
        frame[15] = UInt8(crc & 0xFF)
        frame[16] = UInt8(crc >> 8)

        XCTAssertTrue(isDataFrame(AidexParser.classifyFrame(frame)))
        XCTAssertTrue(AidexParser.validateFrameCRC(frame))
        XCTAssertEqual(AidexParser.parseDataFrame(frame)?.glucoseMgDl, 100)

        frame[15] ^= 0x01
        XCTAssertFalse(AidexParser.validateFrameCRC(frame))
    }

    private func isDataFrame(_ type: AidexParser.FrameType) -> Bool {
        if case .data = type { return true }
        return false
    }
}
