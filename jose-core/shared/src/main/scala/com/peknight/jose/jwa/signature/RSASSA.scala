package com.peknight.jose.jwa.signature

import com.peknight.jose.jwk.KeyType

trait RSASSA extends JWSAlgorithm with com.peknight.security.signature.RSASSA with RSASSAPlatform:
  def keyType: Option[KeyType] = Some(KeyType.RSA)
end RSASSA
