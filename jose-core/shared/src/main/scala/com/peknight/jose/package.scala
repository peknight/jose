package com.peknight

package object jose:
  private[jose] val memberNameMap: Map[String, String] =
    Map(
      "keyType" -> "kty",
      "publicKeyUse" -> "use",
      "keyOperations" -> "key_ops",
      "algorithm" -> "alg",
      "keyID" -> "kid",
      "x509URL" -> "x5u",
      "x509CertificateChain" -> "x5c",
      "x509CertificateSHA1Thumbprint" -> "x5t",
      "x509CertificateSHA256Thumbprint" -> "x5t#S256",

      // EC
      "curve" -> "crv",
      "xCoordinate" -> "x",
      "yCoordinate" -> "y",
      "eccPrivateKey" -> "d",

      // RSA
      "modulus" -> "n",
      "exponent" -> "e",
      "privateExponent" -> "d",
      "firstPrimeFactor" -> "p",
      "secondPrimeFactor" -> "q",
      "firstFactorCRTExponent" -> "dp",
      "secondFactorCRTExponent" -> "dq",
      "firstCRTCoefficient" -> "qi",
      "otherPrimesInfo" -> "oth",

      // oct
      "keyValue" -> "k",

      // JsonWebSignatureHeader
      "jwkSetURL" -> "jku",
      "type" -> "typ",
      "contentType" -> "cty",
      "critical" -> "crit",
    )
end jose
