package com.peknight.jose.jwt

import io.circe.JsonObject

case class JsonWebTokenClaims(
                               issuer: Option[String],
                               subject: Option[String],
                               audience: Option[String],
                               expirationTime: Option[Long],
                               notBefore: Option[Long],
                               issuedAt: Option[Long],
                               jwtId: Option[String],
                               ext: Option[JsonObject]
                             )
object JsonWebTokenClaims:
  private val memberNameMap: Map[String, String] =
    Map(
      "issuer" -> "iss",
      "subject" -> "sub",
      "audience" -> "aud",
      "expirationTime" -> "exp",
      "notBefore" -> "nbf",
      "issuedAt" -> "iat",
      "jwtId" -> "jti"
    )

  
end JsonWebTokenClaims
