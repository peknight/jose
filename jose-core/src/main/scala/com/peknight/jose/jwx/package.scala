package com.peknight.jose

import cats.Id
import cats.syntax.either.*
import cats.syntax.option.*
import com.peknight.codec.base.{Base, BaseAlphabetPlatform}
import com.peknight.codec.circe.parser.decode
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.syntax.encoder.asS
import com.peknight.codec.{Decoder, Encoder}
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.{Charset, StandardCharsets}
import scala.reflect.ClassTag

package object jwx:
  // Json => String
  def jsonEncodeToString(json: Json): String = json.deepDropNullValues.noSpaces
  // A => Json => String
  def encodeToJson[A](a: A)(using Encoder[Id, Json, A]): String = jsonEncodeToString(a.asS[Id, Json])
  // String => ByteVector
  def stringEncodeToBytes(value: String, charset: Charset = StandardCharsets.UTF_8): Either[Error, ByteVector] =
    ByteVector.encodeString(value)(using charset).asError
  // String => ByteVector => Base
  def stringEncodeToBase[B <: Base](value: String, base: BaseAlphabetPlatform[?, B],
                                    charset: Charset = StandardCharsets.UTF_8): Either[Error, B] =
    stringEncodeToBytes(value, charset).map(base.fromByteVector)
  // A => Json => String => ByteVector
  def encodeToJsonBytes[A](a: A, charset: Charset = StandardCharsets.UTF_8)(using Encoder[Id, Json, A])
  : Either[Error, ByteVector] =
    stringEncodeToBytes(encodeToJson(a), charset)
  // A => Json => String => ByteVector => Base
  def encodeToBase[A, B <: Base : ClassTag](a: A, base: BaseAlphabetPlatform[?, B],
                                            charset: Charset = StandardCharsets.UTF_8)
                                           (using Encoder[Id, Json, A]): Either[Error, B] =
    encodeToJsonBytes[A](a, charset).map(base.fromByteVector)
    
  // Bytes => String
  def bytesDecodeToString(bytes: ByteVector, charset: Charset = StandardCharsets.UTF_8): Either[Error, String] =
    bytes.decodeString(using charset).asError
  // ByteVector => String => Json => A
  def bytesDecodeToJson[A](bytes: ByteVector, charset: Charset = StandardCharsets.UTF_8)
                          (using Decoder[Id, Cursor[Json], A]): Either[Error, A] =
    bytesDecodeToString(bytes, charset).flatMap(decode[Id, A])
  // Base => ByteVector => String
  def baseDecodeToString(b: Base, charset: Charset = StandardCharsets.UTF_8): Either[Error, String] =
    b.decode[Id].flatMap(bytes => bytesDecodeToString(bytes, charset))
  // Base => ByteVector => String => Json => A
  def baseDecodeToJson[A](b: Base, charset: Charset = StandardCharsets.UTF_8)(using Decoder[Id, Cursor[Json], A])
  : Either[Error, A] =
    b.decode[Id].flatMap(bytes => bytesDecodeToJson[A](bytes, charset))

  def decodeOption(option: Option[Base]): Either[Error, Option[ByteVector]] =
    option.map(_.decode[Id]) match
      case Some(Right(bytes)) => bytes.some.asRight
      case Some(Left(error)) => error.asLeft
      case None => none.asRight
end jwx
