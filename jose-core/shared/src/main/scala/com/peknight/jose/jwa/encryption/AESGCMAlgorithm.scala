package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.AES

trait AESGCMAlgorithm extends JWEEncryptionAlgorithm:
  def encryption: AES
  def algorithm: String = s"A${encryption.blockSize * 8}GCM"
end AESGCMAlgorithm
