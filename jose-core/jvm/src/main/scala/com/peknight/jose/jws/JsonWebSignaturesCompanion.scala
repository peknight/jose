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
import com.peknight.jose.error.UncheckedBase64UrlEncodePayload
import com.peknight.jose.jws.JsonWebSignature.{encodePayload, encodePayloadJson, encodePayloadString}
import com.peknight.jose.jws.Signature.Signature
import com.peknight.jose.jwx.JosePrimitive
import io.circe.Json
import scodec.bits.ByteVector

import java.nio.charset.Charset

trait JsonWebSignaturesCompanion:
  def signBytes[F[_]: Sync](primitives: NonEmptyList[SigningPrimitive], payload: ByteVector)
  : F[Either[Error, JsonWebSignatures]] =
    handleSignPayloadFunc[F](primitives)(encodePayload(payload, _, _))(_.sequence)

  def signString[F[_]: Sync](primitives: NonEmptyList[SigningPrimitive], payload: String)
  : F[Either[Error, JsonWebSignatures]] =
    handleSignPayloadFunc[F](primitives)(encodePayloadString(payload, _, _))(_.sequence)

  def signJson[F[_], A](primitives: NonEmptyList[SigningPrimitive], payload: A)(using Sync[F], Encoder[Id, Json, A])
  : F[Either[Error, JsonWebSignatures]] =
    handleSignPayloadFunc[F](primitives)(encodePayloadJson(payload, _, _))(_.sequence)

  def sign[F[_]: Sync](primitives: NonEmptyList[SigningPrimitive], payload: String): F[Either[Error, JsonWebSignatures]] =
    handleSignSequenceFunc[F](primitives, payload)(_.sequence)

  def parSignBytes[F[_]: Sync: Parallel](primitives: NonEmptyList[SigningPrimitive], payload: ByteVector)
  : F[Either[Error, JsonWebSignatures]] =
    handleSignPayloadFunc[F](primitives)(encodePayload(payload, _, _))(_.parSequence)

  def parSignString[F[_]: Sync: Parallel](primitives: NonEmptyList[SigningPrimitive], payload: String)
  : F[Either[Error, JsonWebSignatures]] =
    handleSignPayloadFunc[F](primitives)(encodePayloadString(payload, _, _))(_.parSequence)

  def parSignJson[F[_], A](primitives: NonEmptyList[SigningPrimitive], payload: A)
                          (using Sync[F], Parallel[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebSignatures]] =
    handleSignPayloadFunc[F](primitives)(encodePayloadJson(payload, _, _))(_.parSequence)

  def parSign[F[_]: Sync: Parallel](primitives: NonEmptyList[SigningPrimitive], payload: String)
  : F[Either[Error, JsonWebSignatures]] =
    handleSignSequenceFunc[F](primitives, payload)(_.parSequence)

  private def handleSignPayloadFunc[F[_]: Sync](primitives: NonEmptyList[SigningPrimitive])
                                               (encodePayload: (Boolean, Charset) => Either[Error, String])
                                               (sequence: NonEmptyList[F[Either[Error, Signature]]] => F[NonEmptyList[Either[Error, Signature]]])
  : F[Either[Error, JsonWebSignatures]] =
    val either =
      for
        base64UrlEncodePayload <- isBase64UrlEncodePayload(primitives)
        charset <- JosePrimitive.charset(primitives)
        payload <- encodePayload(base64UrlEncodePayload, charset)
      yield
        payload
    either.fold(_.asLeft.pure, payload => handleSignSequenceFunc[F](primitives, payload)(sequence))

  private def handleSignSequenceFunc[F[_]: Sync](primitives: NonEmptyList[SigningPrimitive], payload: String)
                                                (sequence: NonEmptyList[F[Either[Error, Signature]]] => F[NonEmptyList[Either[Error, Signature]]])
  : F[Either[Error, JsonWebSignatures]] =
    sequence(primitives
      .map(primitive => primitive
        .handleSignSignature(payload)((headerBase, signature) => Signature(primitive.header, headerBase, signature))
      )
    ).map(_.sequence.map(signatures => JsonWebSignatures(payload, signatures)))

  private def isBase64UrlEncodePayload(primitives: NonEmptyList[SigningPrimitive]): Either[Error, Boolean] =
    val base64UrlEncodePayload = primitives.head.header.isBase64UrlEncodePayload
    if primitives.tail.forall(_.header.isBase64UrlEncodePayload == base64UrlEncodePayload) then
      base64UrlEncodePayload.asRight
    else
      UncheckedBase64UrlEncodePayload.asLeft
end JsonWebSignaturesCompanion
