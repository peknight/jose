package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.Algorithm
import com.peknight.crypto.algorithm.key.agreement.`ECDH-ES`
import com.peknight.jose.Requirement
import com.peknight.jose.jwa.HeaderParam.{apu, apv, epk}
import com.peknight.jose.Requirement.`Recommended+`

trait ECDHESAlgorithm extends KeyAgreementAlgorithm:
  val headerParams: Seq[HeaderParam] = Seq(epk, apu, apv)
end ECDHESAlgorithm
object ECDHESAlgorithm extends ECDHESAlgorithm:
  val algorithm: Algorithm = `ECDH-ES`
  val requirement: Requirement = `Recommended+`
  private[this] case class ECDHESAlgorithm(algorithm: `ECDH-ES`, requirement: Requirement)
    extends com.peknight.jose.jwa.ECDHESAlgorithm
  def apply(algorithm: `ECDH-ES`, requirement: Requirement): com.peknight.jose.jwa.ECDHESAlgorithm =
    ECDHESAlgorithm(algorithm, requirement)
end ECDHESAlgorithm
