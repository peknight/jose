package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.{AESWrap, AESWrap_256}
import com.peknight.security.mac.{HmacSHA2, HmacSHA512}

object `PBES2-HS512+A256KW` extends PBES2Algorithm:
  val prf: HmacSHA2 = HmacSHA512
  val encryption: AESWrap = AESWrap_256
end `PBES2-HS512+A256KW`
