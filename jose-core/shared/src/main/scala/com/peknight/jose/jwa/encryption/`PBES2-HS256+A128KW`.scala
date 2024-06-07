package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.{AESWrap, AESWrap_128}
import com.peknight.security.mac.{HmacSHA2, HmacSHA256}

object `PBES2-HS256+A128KW` extends PBES2Algorithm:
  val prf: HmacSHA2 = HmacSHA256
  val encryption: AESWrap = AESWrap_128
end `PBES2-HS256+A128KW`
