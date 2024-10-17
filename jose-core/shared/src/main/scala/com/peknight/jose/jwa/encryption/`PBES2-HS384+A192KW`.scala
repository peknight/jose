package com.peknight.jose.jwa.encryption

import com.peknight.security.mac.{HmacSHA2, HmacSHA384}

object `PBES2-HS384+A192KW` extends PBES2Algorithm:
  val prf: HmacSHA2 = HmacSHA384
  val encryption: AESWrapAlgorithm = A192KW
end `PBES2-HS384+A192KW`
