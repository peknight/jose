package com.peknight.jose.jws

import cats.effect.Sync
import cats.syntax.functor.*
import cats.syntax.parallel.*
import cats.syntax.traverse.*
import cats.{Id, Parallel}
import com.peknight.codec.Encoder
import com.peknight.error.Error
import com.peknight.jose.jws.Signature.Signature
import io.circe.Json

trait JsonWebSignaturesCompanion:
  def signJson[F[_], A](primitives: List[SignPrimitive], payload: A)(using Sync[F], Encoder[Id, Json, A])
  : F[Either[Error, JsonWebSignatures]] =
    ???

  def sign[F[_]: Sync](primitives: List[SignPrimitive], payload: String): F[Either[Error, JsonWebSignatures]] =
    handleSign[F](primitives, payload)(_.sequence)

  def parSign[F[_]: Sync: Parallel](primitives: List[SignPrimitive], payload: String): F[Either[Error, JsonWebSignatures]] =
    handleSign[F](primitives, payload)(_.parSequence)

  def handleSign[F[_]: Sync](primitives: List[SignPrimitive], payload: String)
                            (sequence: List[F[Either[Error, Signature]]] => F[List[Either[Error, Signature]]])
  : F[Either[Error, JsonWebSignatures]] =
    sequence(primitives
      .map(primitive => primitive
        .handleSignSignature(payload)((headerBase, signature) => Signature(primitive.header, headerBase, signature))
      )
    ).map(_.sequence.map(signatures => JsonWebSignatures(payload, signatures)))

end JsonWebSignaturesCompanion
