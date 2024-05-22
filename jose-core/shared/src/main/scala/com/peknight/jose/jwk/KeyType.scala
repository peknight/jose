package com.peknight.jose.jwk

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.{Optional, Required, `Recommended+`}

enum KeyType(val name: String, val requirement: Requirement):
  case EllipticCurve extends KeyType("EC", `Recommended+`)
  case RSA extends KeyType("RSA", Required)
  case OctetSequence extends KeyType("oct", Required)

  case OctetKeyPair extends KeyType("OKP", Optional)
end KeyType
