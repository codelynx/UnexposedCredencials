import Foundation
import CommonCrypto


struct AES256Key {

	static let length = Int(kCCKeySizeAES256)
	let key: [UInt8]

	init(string: String) {
		var buffer = [UInt8](repeating: 0, count: Self.length)
		if let data = string.data(using: .utf8) {
			let bytes = [UInt8](data)
			(0 ..< min(bytes.count, Self.length)).forEach { buffer[$0] = bytes[$0] }
		}
		assert(buffer.count == Self.length)
		self.key = buffer
	}

	init?(data: Data) {
		guard data.count == Self.length else { return nil }
		var buffer = [UInt8](repeating: 0, count: Self.length)
		(0 ..< Self.length).forEach { buffer[$0] = data[$0] }
		self.key = buffer
	}
}


extension Data {

	static private let keyLength = Int(kCCKeySizeAES256+1)

	func encryptAES256(key: AES256Key) -> Data? {
		let blockSize = Int(kCCBlockSizeAES128)
		var buffer = [UInt8](repeating: 0, count: self.count + blockSize)
		var numberOfBytesDecrypted: size_t = 0
		let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding),
				key.key, kCCKeySizeAES256,
				nil, // initialization vector (optional)
				(self as NSData).bytes, self.count, // input
				&buffer, buffer.count, // output
				&numberOfBytesDecrypted);
		if status == kCCSuccess {
			return Data(bytes: &buffer, count: Int(numberOfBytesDecrypted))
		}
		return nil
	}

	func decyptAES256(key: AES256Key) -> Data? {
		let blockSize = Int(kCCBlockSizeAES128)
		var buffer = [UInt8](repeating: 0, count: self.count + blockSize)
		var numberOfBytesDecrypted: size_t = 0
		let status = CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding),
				key.key, kCCKeySizeAES256,
				nil, // initialization vector (optional)
				(self as NSData).bytes, self.count, // input
				&buffer, buffer.count, // output
				&numberOfBytesDecrypted);
		if status == kCCSuccess {
			return Data(bytes: &buffer, count: Int(numberOfBytesDecrypted))
		}
		return nil
	}

}
