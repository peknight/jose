package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.RSAES

trait RSAESAlgorithm extends KeyEncryptionAlgorithm with RSAES:
  def headerParams: Seq[HeaderParam] = Seq.empty
end RSAESAlgorithm
