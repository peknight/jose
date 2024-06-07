package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Required
import com.peknight.security.cipher.mode.CBC
import com.peknight.security.cipher.{AES, AES_192, AES_256}
import com.peknight.security.mac.{HmacSHA2, HmacSHA512}

object `A256CBC-HS512` extends AESCBCHmacSHA2Algorithm with AES_256:
  val encryption: AES = AES_256 / CBC
  val mac: HmacSHA2 = HmacSHA512
  val requirement: Requirement = Required
end `A256CBC-HS512`
