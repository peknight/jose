package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.{AESWrap, AESWrap_192}
import com.peknight.security.mac.{HmacSHA2, HmacSHA384}

object `PBES2-HS384+A192KW` extends PBES2Algorithm:
  val prf: HmacSHA2 = HmacSHA384
  val encryption: AESWrap = AESWrap_192
end `PBES2-HS384+A192KW`
