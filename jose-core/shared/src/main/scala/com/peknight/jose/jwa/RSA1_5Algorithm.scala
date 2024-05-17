package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.Algorithm
import com.peknight.crypto.algorithm.ssa.`RSASSA-PKCS1-v1_5`
import com.peknight.jose.jwa.Requirement.`Recommended-`

object RSA1_5Algorithm extends KeyEncryptionAlgorithm:
  val algorithm: Algorithm = `RSASSA-PKCS1-v1_5`
  val headerParams: Seq[HeaderParam] = Seq.empty[HeaderParam]
  val requirement: Requirement = `Recommended-`
end RSA1_5Algorithm
