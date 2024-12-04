package com.peknight.jose.jws

import cats.data.NonEmptyList
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.syntax.parallel.*
import cats.syntax.traverse.*
import cats.{Id, Parallel}
import com.peknight.codec.Encoder
import com.peknight.error.Error
import com.peknight.jose.error.{UncheckedBase64UrlEncodePayload, UncheckedCharset}
import com.peknight.jose.jws.JsonWebSignature.{encodePayload, encodePayloadJson, encodePayloadString}
import com.peknight.jose.jws.Signature.Signature
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.Charset

trait JsonWebSignaturesCompanion:
  def isBase64UrlEncodePayload(primitives: NonEmptyList[SignPrimitive]): Either[Error, Boolean] =
    val base64UrlEncodePayload = primitives.head.header.isBase64UrlEncodePayload
    if primitives.tail.forall(_.header.isBase64UrlEncodePayload == base64UrlEncodePayload) then
      base64UrlEncodePayload.asRight
    else
      UncheckedBase64UrlEncodePayload.asLeft

  def charset(primitives: NonEmptyList[SignPrimitive]): Either[Error, Charset] =
    val charset = primitives.head.context.charset
    if primitives.tail.forall(_.context.charset.equals(charset)) then charset.asRight
    else UncheckedCharset.asLeft

  def signBytes[F[_]: Sync](primitives: NonEmptyList[SignPrimitive], payload: ByteVector)
  : F[Either[Error, JsonWebSignatures]] =
    handleSignBytes[F](primitives, payload)(sign)

  def signString[F[_]: Sync](primitives: NonEmptyList[SignPrimitive], payload: String)
  : F[Either[Error, JsonWebSignatures]] =
    handleSignString[F](primitives, payload)(sign)

  def signJson[F[_], A](primitives: NonEmptyList[SignPrimitive], payload: A)(using Sync[F], Encoder[Id, Json, A])
  : F[Either[Error, JsonWebSignatures]] =
    handleSignJson[F, A](primitives, payload)(sign)

  def sign[F[_]: Sync](primitives: NonEmptyList[SignPrimitive], payload: String): F[Either[Error, JsonWebSignatures]] =
    handleSign[F](primitives, payload)(_.sequence)

  def parSignBytes[F[_]: Sync: Parallel](primitives: NonEmptyList[SignPrimitive], payload: ByteVector)
  : F[Either[Error, JsonWebSignatures]] =
    handleSignBytes[F](primitives, payload)(parSign)

  def parSignString[F[_]: Sync: Parallel](primitives: NonEmptyList[SignPrimitive], payload: String)
  : F[Either[Error, JsonWebSignatures]] =
    handleSignString[F](primitives, payload)(parSign)

  def parSignJson[F[_], A](primitives: NonEmptyList[SignPrimitive], payload: A)
                          (using Sync[F], Parallel[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebSignatures]] =
    handleSignJson[F, A](primitives, payload)(parSign)

  def parSign[F[_]: Sync: Parallel](primitives: NonEmptyList[SignPrimitive], payload: String)
  : F[Either[Error, JsonWebSignatures]] =
    handleSign[F](primitives, payload)(_.parSequence)

  private def handleSignBytes[F[_] : Sync](primitives: NonEmptyList[SignPrimitive], payload: ByteVector)
                                          (f: (NonEmptyList[SignPrimitive], String) => F[Either[Error, JsonWebSignatures]])
  : F[Either[Error, JsonWebSignatures]] =
    doHandleSign[F](primitives)(encodePayload(payload, _, _))(f)

  private def handleSignString[F[_]: Sync](primitives: NonEmptyList[SignPrimitive], payload: String)
                                          (f: (NonEmptyList[SignPrimitive], String) => F[Either[Error, JsonWebSignatures]])
  : F[Either[Error, JsonWebSignatures]] =
    doHandleSign[F](primitives)(encodePayloadString(payload, _, _))(f)

  private def handleSignJson[F[_], A](primitives: NonEmptyList[SignPrimitive], payload: A)
                                     (f: (NonEmptyList[SignPrimitive], String) => F[Either[Error, JsonWebSignatures]])
                                     (using Sync[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebSignatures]] =
    doHandleSign[F](primitives)(encodePayloadJson(payload, _, _))(f)

  private def doHandleSign[F[_]: Sync](primitives: NonEmptyList[SignPrimitive])
                                      (encodePayload: (Boolean, Charset) => Either[Error, String])
                                      (f: (NonEmptyList[SignPrimitive], String) => F[Either[Error, JsonWebSignatures]])
  : F[Either[Error, JsonWebSignatures]] =
    val either =
      for
        base64UrlEncodePayload <- isBase64UrlEncodePayload(primitives)
        charset <- charset(primitives)
        p <- encodePayload(base64UrlEncodePayload, charset)
      yield
        f(primitives, p)
    either.fold(_.asLeft.pure, identity)

  private def handleSign[F[_]: Sync](primitives: NonEmptyList[SignPrimitive], payload: String)
                                    (sequence: NonEmptyList[F[Either[Error, Signature]]] => F[NonEmptyList[Either[Error, Signature]]])
  : F[Either[Error, JsonWebSignatures]] =
    sequence(primitives
      .map(primitive => primitive
        .handleSignSignature(payload)((headerBase, signature) => Signature(primitive.header, headerBase, signature))
      )
    ).map(_.sequence.map(signatures => JsonWebSignatures(payload, signatures)))

end JsonWebSignaturesCompanion
