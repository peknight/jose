package com.peknight.jose.jwt

trait JsonWebTokenClaimsCompanion:
  val issuerLabel: String = "iss"
  val subjectLabel: String = "sub"
  val audienceLabel: String = "aud"
  val expirationTimeLabel: String = "exp"
  val notBeforeLabel: String = "nbf"
  val issuedAtLabel: String = "iat"
  val jwtIDLabel: String = "jti"
  val initialRegisteredClaimNames: Set[String] =
    Set(issuerLabel, subjectLabel, audienceLabel, expirationTimeLabel, notBeforeLabel, issuedAtLabel, jwtIDLabel)
  private[jwt] val memberNameMap: Map[String, String] =
    Map(
      "issuer" -> issuerLabel,
      "subject" -> subjectLabel,
      "audience" -> audienceLabel,
      "expirationTime" -> expirationTimeLabel,
      "notBefore" -> notBeforeLabel,
      "issuedAt" -> issuedAtLabel,
      "jwtID" -> jwtIDLabel,
    )
end JsonWebTokenClaimsCompanion
