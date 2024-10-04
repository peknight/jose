package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Recommended

object `ECDH-ES+A256KW` extends `ECDH-ESWithAESWrapAlgorithm`:
  val encryption: AESWrapAlgorithm = A256KW
  val requirement: Requirement = Recommended
end `ECDH-ES+A256KW`
