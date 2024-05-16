package com.peknight.jose.jwk

enum KeyType(val name: String):
  case RSA extends KeyType("RSA")
  case EllipticCurve extends KeyType("EC")
  case OctetKeyPair extends KeyType("OKP")
  case OctetSequence extends KeyType("oct")
end KeyType
