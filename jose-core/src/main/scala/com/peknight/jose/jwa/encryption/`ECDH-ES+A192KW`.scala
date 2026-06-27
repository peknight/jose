package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional

object `ECDH-ES+A192KW` extends `ECDH-ESWithAESWrapAlgorithm`:
  val encryption: AESWrapAlgorithm = A192KW
  val requirement: Requirement = Optional
end `ECDH-ES+A192KW`
