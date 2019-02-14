Pod::Spec.new do |s|
  s.name         = "TezosCrypto"
  s.version      = "1.0.0"
  s.summary      = "TezosCrypto implements cryography functions for the Tezos Blockchain."

  s.homepage     = "https://github.com/keefertaylor/TezosCrypto"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author             = { "Keefer Taylor" => "keefer@keefertaylor.com" }
  s.source       = { :git => "https://github.com/keefertaylor/TezosCrypto.git", :tag => "1.0.0" }
  s.source_files  = "TezosCrypto/*.swift", "Base58String/*.swift"
  s.swift_version = "4.2"
  s.ios.deployment_target = "8.0"
  s.osx.deployment_target = "10.10"

  s.dependency "Base58Swift" ~> 1.0.2
  s.dependency "BigInt" ~> 3.1
  s.dependency "CryptoSwift" ~> 0.14.0
  s.dependency "Sodium", "~> 0.7.0"  
  
  s.test_spec "Tests" do |test_spec|
    test_spec.source_files = "TezosCryptoTests/*.swift"
  end    
end
