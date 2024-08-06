package com.peknight.jose

import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwk.KeyId
import io.circe.JsonObject

trait JoseHeader:
  def algorithm: Option[JsonWebAlgorithm]
  def keyID: Option[KeyId]
  def `type`: Option[String]
  def contentType: Option[String]
  def ext: Option[JsonObject]
end JoseHeader
