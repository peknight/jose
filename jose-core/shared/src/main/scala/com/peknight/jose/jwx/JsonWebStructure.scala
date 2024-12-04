package com.peknight.jose.jwx

import cats.parse.Parser
import com.peknight.error.Error
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jws.JsonWebSignature

trait JsonWebStructure extends HeaderEither with JsonWebStructurePlatform:
  def isNestedJsonWebToken: Either[Error, Boolean] =
    getUnprotectedHeader.map(_.contentType.exists(cty =>
      "jwt".equalsIgnoreCase(cty) || "application/jwt".equalsIgnoreCase(cty)
    ))
end JsonWebStructure
object JsonWebStructure:
  def parse(value: String): Either[Parser.Error, JsonWebStructure] =
    JsonWebEncryption.parse(value).orElse(JsonWebSignature.parse(value))
end JsonWebStructure
