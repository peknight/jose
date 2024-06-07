package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended
import com.peknight.security.cipher.{AESWrap, AESWrap_256}

object `ECDH-ES+A256KW` extends `ECDH-ESUsingConcatKDFAndCEKWithAESWrap`:
  val encryption: AESWrap = AESWrap_256
  val requirement: Requirement = Recommended
end `ECDH-ES+A256KW`
