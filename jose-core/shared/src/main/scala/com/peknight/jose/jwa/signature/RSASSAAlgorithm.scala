package com.peknight.jose.jwa.signature

import com.peknight.security.digest.`SHA-2`
import com.peknight.security.signature.DigestWithEncryption

trait RSASSAAlgorithm extends JWSAlgorithm:
  def digest: `SHA-2`
  def signature: DigestWithEncryption
end RSASSAAlgorithm
