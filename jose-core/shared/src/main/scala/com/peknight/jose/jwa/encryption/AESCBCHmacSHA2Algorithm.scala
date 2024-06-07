package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.AES
import com.peknight.security.cipher.mode.{CBC, CipherAlgorithmMode}
import com.peknight.security.mac.HmacSHA2

trait AESCBCHmacSHA2Algorithm extends JWEEncryptionAlgorithm with AES:
  override val mode: CipherAlgorithmMode = CBC
  def mac: HmacSHA2
  override def algorithm: String = s"A${blockSize * 8}CBC-HS${mac.digest.bitLength}"
end AESCBCHmacSHA2Algorithm
