//
//	Data+AES.swift
//	ZKit
//
//	Created by Kaz Yoshikawa on 10/15/19.
//	Copyright © 2019 Electricwoods LLC. All rights reserved.
//

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

/*
func prompt(_ prompt: String) -> Bool {
	while true {
		print("\(prompt) (Y/N)")
		if let response = readLine()?.uppercased() {
			if response == "Y" {
				return true
			} else if response == "N" {
				return false
			} else {
				print("Invalid response.")
			}
		} else {
			print("Invalid response.")
		}
	}
}
*/

func abort(_ message: String) -> Never {
	print(message)
	exit(1)
}

public extension String {
	func appendingPathExtension(_ str: String) -> String? {
		return (self as NSString).appendingPathExtension(str)
	}
	func appendingPathComponent(_ str: String) -> String {
		return (self as NSString).appendingPathComponent(str)
	}
	var deletingPathExtension: String {
		return (self as NSString).deletingPathExtension
	}
	var deletingLastPathComponent: String {
		return (self as NSString).deletingLastPathComponent
	}
	var abbreviatingWithTildeInPath: String {
		return (self as NSString).abbreviatingWithTildeInPath;
	}
	var expandingTildeInPath: String {
		return (self as NSString).expandingTildeInPath;
	}
	var fileSystemRepresentation: UnsafePointer<Int8> {
		return (self as NSString).fileSystemRepresentation
	}
	var lastPathComponent: String {
		return (self as NSString).lastPathComponent
	}
	var pathExtension: String {
		return (self as NSString).pathExtension
	}
	var pathComponents: [String] {
		return (self as NSString).pathComponents
	}
}


do {
	let currentDirectoryPath =  FileManager.default.currentDirectoryPath
	
	// make sure current directory is .credentials, or there may be some design changes
	if !(currentDirectoryPath.lastPathComponent == ".credentials") {
		abort("current directory is is not '.credentials', something has changed")
	}

	// make AES 256 key, its okay to keep generating new keys because key and encripted data are always from the same code
	let keyLength = AES256Key.length // 32
	var sharedKeyBin = Data(count: keyLength)
	let result = sharedKeyBin.withUnsafeMutableBytes {
		SecRandomCopyBytes(kSecRandomDefault, keyLength, $0.baseAddress!)
	}
	guard result == errSecSuccess
	else { abort("error: failed generating random 256 bit data") }
	
	// reading credentials.plist
	let credentialsFile = "credentials.plist"
	let credentialsFilePath = currentDirectoryPath.appendingPathComponent(credentialsFile)
	let credentialsFileBin: Data = {
		guard let bin = NSData(contentsOfFile: credentialsFilePath)
		else { abort("error: \(credentialsFile) not found.") }
		return bin as Data
	}()
	
	guard let aes256Key = AES256Key(data: sharedKeyBin)
	else { abort("error: failed to create AES256Key") }
	
	// encrypt
	guard let encryptedCredentialsFileBin = credentialsFileBin.encryptAES256(key: aes256Key)
	else { abort("error: failed to encrypt credentials contents.") }
	
	// decypt for verifying
	guard let decryptedCredentialsFileBin = encryptedCredentialsFileBin.decyptAES256(key: aes256Key)
	else { abort("error: failed to decrypt encrypted credentials contents") }

	// verify encryption and decryption
	guard credentialsFileBin == decryptedCredentialsFileBin
	else { abort("error: credential contents and decrypted credentials contents are different.") }

	let aes256sourceFile = "AES256.swift"
	let aes256sourcePath = currentDirectoryPath.appendingPathComponent(aes256sourceFile)
	
	var usedEncoding: String.Encoding = .utf8
	let aes256source = try String(contentsOfFile: aes256sourcePath, usedEncoding: &usedEncoding)

	// due to avoid class name start with numeric number, add
	let credentialsClass = {
		let uuid = UUID().uuidString.replacingOccurrences(of: "-", with: "")
		return "C" +  uuid.dropFirst()
	}()

	
	let aesKeyHexadecimalString = sharedKeyBin.map { String(format: "0x%02x", $0) }.joined(separator: ",")
	let encryptedCredentialsHexadecimalString = encryptedCredentialsFileBin.map { String(format: "0x%02x", $0) }.joined(separator: ",")
	let sourceString = """
	\(aes256source)
	let aesKeyBin = Data([\(aesKeyHexadecimalString)])
	let aesKey = AES256Key(data: aesKeyBin)!
	let encryptedBin = Data([\(encryptedCredentialsHexadecimalString)])
	let decryptedBin = encryptedBin.decyptAES256(key: aesKey)!
	
	class \(credentialsClass) {
		static let shared = \(credentialsClass)()
		let dictionary: [String: Any]?
		private init() {
			dictionary = try? PropertyListSerialization.propertyList(from: decryptedBin, options: [], format: nil) as? [String: Any]
		}
		subscript(key: String) -> Any? {
			return dictionary?[key]
		}
	}
	typealias CREDENTIALS = \(credentialsClass)
	"""

	let credentialsSourceFile = "Credentials.swift"
	let credentialsSourcePath = currentDirectoryPath.appendingPathComponent(credentialsSourceFile)
	try sourceString.write(toFile: credentialsSourcePath, atomically: true, encoding: .utf8)
	print(sourceString)
}
catch {
	abort("\(error)")
}
