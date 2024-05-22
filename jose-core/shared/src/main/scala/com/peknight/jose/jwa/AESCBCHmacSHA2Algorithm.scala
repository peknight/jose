package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.cipher.EncryptionWithMAC
import com.peknight.jose.Requirement

case class AESCBCHmacSHA2Algorithm(algorithm: EncryptionWithMAC, requirement: Requirement) extends JWEEncryptionAlgorithm
