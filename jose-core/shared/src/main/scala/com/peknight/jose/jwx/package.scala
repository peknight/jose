package com.peknight.jose

import cats.Id
import com.peknight.codec.{Decoder, Encoder}
import com.peknight.codec.base.{Base, BaseAlphabetPlatform}
import com.peknight.codec.circe.parser.decode
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.syntax.encoder.asS
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import io.circe.Json
import scodec.bits.ByteVector

import scala.reflect.ClassTag

package object jwx:
  def toBytes(value: String): Either[Error, ByteVector] = ByteVector.encodeUtf8(value).asError
  def toJsonBytes[T](t: T)(using Encoder[Id, Json, T]): Either[Error, ByteVector] =
    toBytes(t.asS[Id, Json].deepDropNullValues.noSpaces)
  def toBase[T, B <: Base : ClassTag](t: T, base: BaseAlphabetPlatform[?, B])(using Encoder[Id, Json, T])
  : Either[Error, B] =
    toJsonBytes[T](t).map(base.fromByteVector)
  def fromBase[T](b: Base)(using Decoder[Id, Cursor[Json], T]): Either[Error, T] =
    for
      bytes <- b.decode[Id]
      jsonString <- bytes.decodeUtf8.asError
      t <- decode[Id, T](jsonString)
    yield t
end jwx
