package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.cipher.{AESWrap, AESWrap_192}

object `ECDH-ES+A192KW` extends `ECDH-ESWithAESWrapAlgorithm`:
  val encryption: AESWrap = AESWrap_192
  val requirement: Requirement = Optional
end `ECDH-ES+A192KW`
