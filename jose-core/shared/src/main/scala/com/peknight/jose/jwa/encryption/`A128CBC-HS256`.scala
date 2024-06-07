package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Required
import com.peknight.security.cipher.AES_128
import com.peknight.security.mac.{HmacSHA2, HmacSHA256}

object `A128CBC-HS256` extends AESCBCHmacSHA2Algorithm with AES_128:
  val mac: HmacSHA2 = HmacSHA256
  val requirement: Requirement = Required
end `A128CBC-HS256`
