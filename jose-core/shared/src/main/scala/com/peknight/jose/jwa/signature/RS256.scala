package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Recommended
import com.peknight.security.digest.{`SHA-256`, `SHA-2`}

object RS256 extends `RSASSA-PKCS1-v1_5Algorithm`:
  val digest: `SHA-2` = `SHA-256`
  val requirement: Requirement = Recommended
end RS256
