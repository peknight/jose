package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.cipher.Transformation
import com.peknight.jose.Requirement

case class AESGCMAlgorithm(algorithm: Transformation, requirement: Requirement) extends JWEEncryptionAlgorithm
