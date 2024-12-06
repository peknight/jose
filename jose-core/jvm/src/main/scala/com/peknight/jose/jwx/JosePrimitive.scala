package com.peknight.jose.jwx

import cats.data.NonEmptyList
import cats.syntax.either.*
import com.peknight.error.Error
import com.peknight.jose.error.UncheckedCharset

import java.nio.charset.Charset

trait JosePrimitive:
  def configuration: JoseConfiguration
end JosePrimitive
object JosePrimitive:
  def charset(primitives: NonEmptyList[JosePrimitive]): Either[Error, Charset] =
    val charset = primitives.head.configuration.charset
    if primitives.tail.forall(_.configuration.charset.equals(charset)) then charset.asRight
    else UncheckedCharset.asLeft
end JosePrimitive
