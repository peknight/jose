package com.peknight.jose.jwa.signature

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.security.digest.`SHA-2`
import com.peknight.security.mgf.{MGF, MGF1}
import com.peknight.security.signature.`RSASSA-PSS`

trait `RSASSA-PSSAlgorithm` extends JWSAlgorithm with `RSASSA-PSS`:
  def digest: `SHA-2`
  def mgf: MGF = MGF1
  def requirement: Requirement = Optional
  override def algorithm: String = s"PS${digest.bitLength}"
end `RSASSA-PSSAlgorithm`
