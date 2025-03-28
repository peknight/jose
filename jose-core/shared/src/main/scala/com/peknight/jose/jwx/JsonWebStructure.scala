package com.peknight.jose.jwx

import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jws.JsonWebSignature

trait JsonWebStructure extends HeaderIor with JsonWebStructurePlatform:
  def compact: Either[Error, String]
  def getMergedHeader: Either[Error, JoseHeader]
end JsonWebStructure
object JsonWebStructure:
  def parse(value: String): Either[Error, JsonWebStructure] =
    JsonWebEncryption.parse(value).orElse(JsonWebSignature.parse(value)).asError
end JsonWebStructure
