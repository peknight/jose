package com.peknight

package object jose:
  val jwtType: String = "JWT"
  private[jose] val memberNameMap: Map[String, String] =
    Map(
      "algorithm" -> "alg",
      "keyID" -> "kid",
      "x509URL" -> "x5u",
      "x509CertificateChain" -> "x5c",
      "x509CertificateSHA1Thumbprint" -> "x5t",
      "x509CertificateSHA256Thumbprint" -> "x5t#S256",

      // headers
      "jwkSetURL" -> "jku",
      "type" -> "typ",
      "contentType" -> "cty",
      "critical" -> "crit",
      "encryptionAlgorithm" -> "enc",
      "compressionAlgorithm" -> "zip",
    )

end jose
