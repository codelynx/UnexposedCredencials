#  Unexposing secret information such as API Key, secret key and others

## Motivation

These days there are so many SDK or services requires API key or secret keys, and often run into sample code for the usage of 
their sercice something like this.  Ok, it's clear that SDK requires some secret infomation to pass to SDK.

I know some developer embeed those secret information to Info.plist, and read them by code.  But if you have inspect your
ipa of your app.  You will find those secret keys are in info.plist without encrypted.  You may wonder what hacker can do
with those keys.  

```swift
	MyGreateService(apiKey: "1234", secretKey:"abcd")
```

Or you may, hard coded like above but hacker may disabbembly your code to get theose secret value.  Of cause it may not be easy,
but imagine this SDK is public, and you can build a project using this SDK, you have own api-key `6789` and secret-key `wxyz`,
then build you app, you sence that this `6789` or `wxyz` is embbed somewhere in your app binary.  So you can search `wxyz`
and you will find the binary code around the part, then you can take a look at targetted application binary to find the simmilar
binary pattern.  I have not tried, but I am wonderig it may be easier to crack the code than you think.   


I am not a security expert but I like to solve this problem. Yes, there may be better way out there.  But I like to solve this
probelm for my brain excerrise.


## Goal

This solution is not for security agency level, I don't expect to protect the secret keys from NSA class agency for cracking.
It should be sufficient to prevent cracking from average casual hackers.


## .credencials

I provide `.credencials` directory this is where you can play with credencial information.  To add or not to add this directory
to source control is depends on your use case.  It may be better not to begin with dot for this directory, but I can change it
later when necessary.

### `credentials.plist`

There is a property lis file `credentials.plist` in the directory, to make this solution simple, this solution assume there is
`credentials.plist` and all sensitive informations are kept in the form of `.plist`. So you can add as many key value based
secret information as possible, but remember do not place large binary or large number of key and value pairs.  Try make it
small as possible.

Then you run this script.  This script reads `credentials.plist` and produce `Credentials.swift` which can be added to
your Xcode project.

Please be aware that you should never add `credentials.plist` to your project, it ruins all this processes.

```bash
./configure
```

In fact, `configure.sh` execute `codegen.swift` as a script, it may affect by updating swift version, so we may need some
mechanisms to prevent swift version issues, but for now, just be aware of the issue. 

### `Credentials.swift`

Here is the produced swift source code.  Remember when you made any changes to `credentials.plist`, don't forget to execute `./configure`. 

```swift
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

let aesKeyBin = Data([0xaa,0xda,0xfd,0x38,0x3f,0x3f,0x3d,0xe6,0x18,0xab,0x06,0x02,0x8a,0x99,0x65,0x4c,0x3d,0x41,0x65,0xea,0x00,0xf9,0x36,0x76,0xe6,0x57,0x71,0x2e,0x15,0x9f,0xb4,0x7f])
let aesKey = AES256Key(data: aesKeyBin)!
let encryptedBin = Data([0xd0,0xb2,0x82,0x17,0xaf,0xf7,0x62,0x50,0xde,0xcd,0xa1,0xc2,0x0f,0xcb,0x45,0x53,0xb5,0xc5,0x84,0x9f,0x32,0x8b,0x9e,0xd7,0xf9,0x1b,0x96,0xe0,0xad,0x19,0xd8,0xca,0x2e,0x5d,0xd2,0x07,0x24,0x0e,0x9f,0xa7,0x64,0x17,0xd4,0x7c,0xc7,0x24,0x0c,0x0f,0x17,0x9e,0x55,0x82,0x47,0x44,0x24,0xba,0x55,0x88,0x86,0x17,0xb8,0x29,0x1c,0xd0,0x0a,0x3b,0x55,0x67,0xd1,0xf5,0x58,0x41,0x4a,0x6f,0x3e,0x90,0x6d,0xe3,0xd5,0xe2,0xb8,0x47,0x87,0xaf,0xc0,0x81,0xd9,0xb5,0x03,0x31,0xb1,0x41,0x52,0x44,0xba,0xb9,0x9a,0x3b,0x06,0xed,0x0a,0x28,0xdb,0x07,0x1b,0xe2,0xf5,0xbd,0xb7,0x13,0xca,0x7a,0xcd,0x3e,0xa8,0x1f,0xce,0xc6,0xea,0xea,0x95,0x89,0xb7,0xea,0x58,0x1e,0x93,0xfb,0x50,0x66,0xdb,0x72,0x2c,0x97,0x98,0x6d,0xe6,0x5a,0x28,0xd8,0x7f,0x1f,0x53,0x47,0x84,0x8b,0xed,0x8c,0x0a,0xdc,0x80,0xf1,0xfe,0x48,0xbb,0xeb,0xaf,0xd6,0x32,0xc0,0x94,0x49,0x39,0xf9,0x91,0xba,0x7b,0xb7,0x11,0x1f,0x76,0x8f,0xcf,0x99,0xe5,0x2d,0x6d,0x22,0xa7,0x4d,0x10,0x66,0x4c,0x09,0x63,0x55,0x2d,0xc2,0x7c,0x99,0x6c,0x6f,0x39,0x6a,0xf1,0x2c,0x4b,0x92,0xcc,0xf9,0x6e,0x3a,0x4f,0xed,0x90,0xc6,0x49,0x6e,0x8a,0x27,0xd9,0x54,0x94,0x84,0x91,0xc9,0xf3,0xdc,0xfa,0xf7,0xa3,0x64,0x75,0x3a,0x97,0xa9,0xc7,0xa7,0x74,0x8a,0x9e,0x40,0x85,0xdc,0xa9,0x2e,0x7d,0x21,0xd0,0x5a,0x90,0x50,0x6d,0x53,0x9f,0x2a,0x31,0xc3,0x3c,0xd4,0xf9,0xee,0x0f,0xe2,0xe0,0x53,0x81,0xd2,0x53,0xda,0xdf,0x01,0x7b,0x90,0xd8,0x7f,0x33,0x24,0x95,0xa7,0x4b,0x96,0xcc,0x4b,0x25,0x5e,0x61,0x86,0x63,0xee,0x52,0x7c,0x30,0x82,0x9a,0x0c,0x22,0x61])
let decryptedBin = encryptedBin.decyptAES256(key: aesKey)!

class CBBA33F3DC70A4502851183DCF579CB1E {
	static let shared = CBBA33F3DC70A4502851183DCF579CB1E()
	let dictionary: [String: Any]?
	private init() {
		dictionary = try? PropertyListSerialization.propertyList(from: decryptedBin, options: [], format: nil) as? [String: Any]
	}
	subscript(key: String) -> Any? {
		return dictionary?[key]
	}
}
typealias CREDENTIALS = CBBA33F3DC70A4502851183DCF579CB1E
```

## Your Xcode project

Now you can safly use credencial information for you app.

```swift
	let my_api_key = CREDENTIALS.shared["MY_API_KEY"] as! String
	let my_secert_key = CREDENTIALS.shared["MY_SECERT_KEY"] as! String 
	MyGreateService(apiKey: my_api_key, secretKey:my_secert_key)
```

### What the heck is CBBA33F3DC70A4502851183DCF579CB1E?

This code uses CREDENTIALS as a typalias of CBBA33F3DC70A4502851183DCF579CB1E.  Because class CREDENTIALS can be exposed by
class dump or other equvalent tools.  So this solution creates UUID like class name with CREDENTIALS typalias.  Then name
`CREDENTIALS` may not be exposed as a symbol.

You may change `MY_API_KEY` or `MY_SECERT_KEY` to random generated string but code readabilty way down hard to read the code.
So it is up to you for the key name.

## Why shared key is not saved as a file?

Since both shared key and encrypted contents are kept in the same source, when the shared key is changed its encrypted contents
are chnaged anyway, so it is okay to re-generate shared key as many as you want.

## Environment

Here is the swift version at this moment of writing this article.

```txt
swift-driver version: 1.75.2 Apple Swift version 5.8 (swiftlang-5.8.0.124.2 clang-1403.0.22.11.100)
Target: arm64-apple-macosx13.0
```  
