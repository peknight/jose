package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.digest.{`SHA-2`, `SHA-512`}

object RS512 extends `RSASSA-PKCS1-v1_5Algorithm`:
  val digest: `SHA-2` = `SHA-512`
  val requirement: Requirement = Optional
end RS512
