package com.peknight

package object jose:
  private[jose] val base64UrlEncodePayloadLabel: String = "b64"
  private[jose] val algorithmLabel: String = "alg"
  private[jose] val encryptionAlgorithmLabel: String = "enc"
  private[jose] val compressionAlgorithmLabel: String = "zip"
  private[jose] val memberNameMap: Map[String, String] =
    Map(
      "algorithm" -> algorithmLabel,
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
      "encryptionAlgorithm" -> encryptionAlgorithmLabel,
      "compressionAlgorithm" -> compressionAlgorithmLabel,

      "ephemeralPublicKey" -> "epk",
      "agreementPartyUInfo" -> "apu",
      "agreementPartyVInfo" -> "apv",

      "initializationVector" -> "iv",
      "authenticationTag" -> "tag",

      "pbes2SaltInput" -> "p2s",
      "pbes2Count" -> "p2c",

      // rfc7797
      "base64UrlEncodePayload" -> base64UrlEncodePayloadLabel,
    )
end jose
