Pod::Spec.new do |s|
  s.name         = "TezosCrypto"
  s.version      = "2.1.5"
  s.summary      = "TezosCrypto implements cryptography functions for the Tezos Blockchain."

  s.homepage     = "https://github.com/keefertaylor/TezosCrypto"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author             = { "Keefer Taylor" => "keefer@keefertaylor.com" }
  s.source       = { :git => "https://github.com/keefertaylor/TezosCrypto.git", :tag => "2.1.5" }
  s.source_files  = "TezosCrypto/*.swift", "Base58String/*.swift"
  s.swift_version = "4.2"
  s.ios.deployment_target = "10.0"
  s.osx.deployment_target = "10.14"

  s.dependency "Base58Swift", "~> 2.1.0"
  s.dependency "BigInt", "~> 3.1"
  s.dependency "CryptoSwift", "~> 0.14.0"
  s.dependency "Sodium", "~> 0.8.0"
  s.dependency "MnemonicKit", "~> 1.3.7"

  s.test_spec "Tests" do |test_spec|
    test_spec.source_files = "TezosCryptoTests/*.swift"
  end
end
