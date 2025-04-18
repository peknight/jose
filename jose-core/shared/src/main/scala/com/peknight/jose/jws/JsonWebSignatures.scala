package com.peknight.jose.jws

import cats.Monad
import cats.data.NonEmptyList
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.config.given
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.*
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.jose.jws.Signature.Signature
import com.peknight.jose.jws.Signature.Signature.codecSignature
import io.circe.{Json, JsonObject}

case class JsonWebSignatures(payload: String, signatures: NonEmptyList[Signature]):
  def toList: NonEmptyList[JsonWebSignature] =
    signatures.map(signature => JsonWebSignature(signature.headerIor, payload, signature.signature))
end JsonWebSignatures
object JsonWebSignatures extends JsonWebSignaturesCompanion:
  given codecJsonWebSignatures[F[_], S](using
    Monad[F], ObjectType[S], NullType[S], ArrayType[S], BooleanType[S], NumberType[S], StringType[S],
    Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JsonWebSignatures] =
    Codec.derived[F, S, JsonWebSignatures]

  given jsonCodecJsonWebSignatures[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebSignatures] =
    codecJsonWebSignatures[F, Json]

  given circeCodecJsonWebSignatures: io.circe.Codec[JsonWebSignatures] = codec[JsonWebSignatures]
end JsonWebSignatures
