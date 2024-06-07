package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.cipher.mode.CBC
import com.peknight.security.cipher.{AES, AES_192}
import com.peknight.security.mac.{HmacSHA2, HmacSHA384}

object `A192CBC-HS384` extends AESCBCHmacSHA2Algorithm with AES_192:
  val encryption: AES = AES_192 / CBC
  val mac: HmacSHA2 = HmacSHA384
  val requirement: Requirement = Optional
end `A192CBC-HS384`
