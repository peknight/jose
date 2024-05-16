package com.peknight.jose.jwk

enum PublicKeyUseType(val entryName: String):
  case Signature extends PublicKeyUseType("sig")
  case Encryption extends PublicKeyUseType("enc")
end PublicKeyUseType
