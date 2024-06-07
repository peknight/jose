package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwa.encryption.HeaderParam.{apu, apv, epk}

trait `ECDH-ESAlgorithm` extends KeyAgreementAlgorithm:
  def headerParams: Seq[HeaderParam] = Seq(epk, apu, apv)
end `ECDH-ESAlgorithm`
