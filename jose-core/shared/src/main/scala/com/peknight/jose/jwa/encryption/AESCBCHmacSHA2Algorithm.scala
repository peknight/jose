package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.AES
import com.peknight.security.mac.HmacSHA2

trait AESCBCHmacSHA2Algorithm extends JWEEncryptionAlgorithm:
  def encryption: AES
  def mac: HmacSHA2
  def algorithm: String = s"A${encryption.blockSize * 8}CBC-HS${mac.digest.bitLength}"
end AESCBCHmacSHA2Algorithm
