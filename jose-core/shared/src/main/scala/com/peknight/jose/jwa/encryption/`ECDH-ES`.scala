package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.`Recommended+`

object `ECDH-ES` extends `ECDH-ESAlgorithm`:
  val requirement: Requirement = `Recommended+`
  override val algorithm: String = "ECDH-ES"
end `ECDH-ES`
