package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwa.encryption.HeaderParam.{apu, apv, epk}
import com.peknight.security.key.agreement.ECDH

trait `ECDH-ESAlgorithm` extends KeyAgreementAlgorithm with ECDH:
  override def headerParams: Seq[HeaderParam] = Seq(epk, apu, apv)
end `ECDH-ESAlgorithm`
