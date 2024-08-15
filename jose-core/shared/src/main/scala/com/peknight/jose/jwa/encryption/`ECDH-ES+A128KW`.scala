package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Recommended
import com.peknight.security.cipher.{AESWrap, AESWrap_128}

object `ECDH-ES+A128KW` extends `ECDH-ESUsingConcatKDFAndCEKWithAESWrap`:
  val encryption: AESWrap = AESWrap_128
  val requirement: Requirement = Recommended
end `ECDH-ES+A128KW`
