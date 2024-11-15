package com.peknight.jose.jwk

import cats.Monad
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.{Codec, Decoder, Encoder}
import io.circe.{Json, JsonObject}

case class JsonWebKeySet(keys: List[JsonWebKey])
object JsonWebKeySet:
  def apply(keys: JsonWebKey*): JsonWebKeySet = JsonWebKeySet(keys.toList)
  given codecJsonWebKeySet[F[_], S](using Monad[F], ObjectType[S], NullType[S], ArrayType[S], StringType[S],
                                    Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject])
  : Codec[F, S, Cursor[S], JsonWebKeySet] =
    given CodecConfiguration = JsonWebKey.jsonWebKeyCodecConfiguration
    given Encoder[F, S, List[JsonWebKey]] = Encoder.encodeListA[F, S, JsonWebKey]
    given Decoder[F, Cursor[S], List[JsonWebKey]] = Decoder.decodeSeqIgnoreError[F, S, JsonWebKey, List](List.newBuilder)
    Codec.derived[F, S, JsonWebKeySet]
  given jsonCodecJsonWebKeySet[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebKeySet] =
    codecJsonWebKeySet[F, Json]
  given circeCodecJsonWebKeySet: io.circe.Codec[JsonWebKeySet] = codec[JsonWebKeySet]
end JsonWebKeySet