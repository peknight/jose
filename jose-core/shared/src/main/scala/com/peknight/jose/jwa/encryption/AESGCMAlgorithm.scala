package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.AES
import com.peknight.security.cipher.mode.{CipherAlgorithmMode, GCM}

trait AESGCMAlgorithm extends JWEEncryptionAlgorithm with AES:
  override val mode: CipherAlgorithmMode = GCM
  override def algorithm: String = s"A${blockSize * 8}GCM"
end AESGCMAlgorithm
