# ***NOTE:***
Forward development of this library has moved to [TezosKit's Crypto folder](https://github.com/keefertaylor/TezosKit/tree/master/TezosKit/Crypto). 


# TezosCrypto

[![Build Status](https://travis-ci.org/keefertaylor/TezosCrypto.svg?branch=master)](https://travis-ci.org/keefertaylor/TezosCrypto)
[![codecov](https://codecov.io/gh/keefertaylor/TezosCrypto/branch/master/graph/badge.svg)](https://codecov.io/gh/keefertaylor/TezosCrypto)
[![Carthage Compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![Version](https://img.shields.io/cocoapods/v/TezosCrypto.svg?style=flat)](http://cocoapods.org/pods/TezosCrypto)
[![License](https://img.shields.io/cocoapods/l/TezosCrypto.svg?style=flat)](http://cocoapods.org/pods/TezosCrypto)

TezosCrypto implements cryography functions for the [Tezos Blockchain](https://tezos.com).

Donations help me find time to work on TezosCrypto. If you find the library useful, please consider donating to support ongoing develoment.

|Currency| Address |
|---------|---|
| __Tezos__ | tz1SNXT8yZCwTss2YcoFi3qbXvTZiCojx833 |

## Installation

### CocoaPods
TezosCrypto supports installation via CocoaPods. You can depened on TezosCrypto by adding the following to your Podfile:

```
pod "TezosCrypto"
```

### Carthage

If you use [Carthage](https://github.com/Carthage/Carthage) to manage your dependencies, simply add
TezosCrypto to your `Cartfile`:

 ```
github "keefertaylor/TezosCrypto"
```

If you use Carthage to build your dependencies, make sure you have added  `BitInt.framework`, `CryptoSwift.framework`, `MnemonicKit.framework`, `SipHash.framework` and  `Sodium.framework` to the "_Linked Frameworks and Libraries_" section of your target, and have included them in your Carthage framework copying build phase.

### LibSodium Errors

If you receive build errors about missing headers for Sodium, you need to install the LibSodium library.

The easiest way to do this is with Homebrew:

```shell
$ brew update && brew install libsodium
```

## Contributing

Please do.

To get set up:
```shell
$ brew install xcodegen # if you don't already have it
$ xcodegen generate # Generate an XCode project from Project.yml
$ open TezosCrypto.xcodeproj 
```

## License

MIT
