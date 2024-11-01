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
import com.peknight.jose.jws.JsonWebSignature.{encodePayload, encodePayloadJson}
import com.peknight.jose.jws.Signature.Signature
import io.circe.Json
import scodec.bits.ByteVector

trait JsonWebSignaturesCompanion:
  def isBase64UrlEncodePayload(primitives: NonEmptyList[SignPrimitive]): Either[Error, Boolean] =
    val base64UrlEncodePayload = primitives.head.header.isBase64UrlEncodePayload
    if primitives.tail.forall(_.header.isBase64UrlEncodePayload == base64UrlEncodePayload) then
      base64UrlEncodePayload.asRight
    else
      UncheckedBase64UrlEncodePayload.asLeft

  def signJson[F[_], A](primitives: NonEmptyList[SignPrimitive], payload: A)(using Sync[F], Encoder[Id, Json, A])
  : F[Either[Error, JsonWebSignatures]] =
    handleSignJson[F, A](primitives, payload)(sign)

  def signBytes[F[_]: Sync](primitives: NonEmptyList[SignPrimitive], payload: ByteVector)
  : F[Either[Error, JsonWebSignatures]] =
    handleSignBytes[F](primitives, payload)(sign)

  def sign[F[_]: Sync](primitives: NonEmptyList[SignPrimitive], payload: String): F[Either[Error, JsonWebSignatures]] =
    handleSign[F](primitives, payload)(_.sequence)

  def parSignJson[F[_], A](primitives: NonEmptyList[SignPrimitive], payload: A)
                          (using Sync[F], Parallel[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebSignatures]] =
    handleSignJson[F, A](primitives, payload)(parSign)

  def parSignBytes[F[_]: Sync: Parallel](primitives: NonEmptyList[SignPrimitive], payload: ByteVector)
  : F[Either[Error, JsonWebSignatures]] =
    handleSignBytes[F](primitives, payload)(parSign)

  def parSign[F[_]: Sync: Parallel](primitives: NonEmptyList[SignPrimitive], payload: String): F[Either[Error, JsonWebSignatures]] =
    handleSign[F](primitives, payload)(_.parSequence)

  def handleSignJson[F[_], A](primitives: NonEmptyList[SignPrimitive], payload: A)
                             (f: (NonEmptyList[SignPrimitive], String) => F[Either[Error, JsonWebSignatures]])
                             (using Sync[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebSignatures]] =
    val either =
      for
        base64UrlEncodePayload <- isBase64UrlEncodePayload(primitives)
        p <- encodePayloadJson(payload, base64UrlEncodePayload)
      yield
        f(primitives, p)
    either.fold(_.asLeft.pure, identity)

  def handleSignBytes[F[_] : Sync](primitives: NonEmptyList[SignPrimitive], payload: ByteVector)
                                             (f: (NonEmptyList[SignPrimitive], String) => F[Either[Error, JsonWebSignatures]])
  : F[Either[Error, JsonWebSignatures]] =
    val either =
      for
        base64UrlEncodePayload <- isBase64UrlEncodePayload(primitives)
        p <- encodePayload(payload, base64UrlEncodePayload)
      yield
        f(primitives, p)
    either.fold(_.asLeft.pure, identity)

  def handleSign[F[_]: Sync](primitives: NonEmptyList[SignPrimitive], payload: String)
                            (sequence: NonEmptyList[F[Either[Error, Signature]]] => F[NonEmptyList[Either[Error, Signature]]])
  : F[Either[Error, JsonWebSignatures]] =
    sequence(primitives
      .map(primitive => primitive
        .handleSignSignature(payload)((headerBase, signature) => Signature(primitive.header, headerBase, signature))
      )
    ).map(_.sequence.map(signatures => JsonWebSignatures(payload, signatures)))

end JsonWebSignaturesCompanion
