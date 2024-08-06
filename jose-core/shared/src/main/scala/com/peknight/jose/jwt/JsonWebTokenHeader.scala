package com.peknight.jose.jwt

import cats.Monad
import com.peknight.codec.Decoder.decodeOptionAOU
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.string.cases.SnakeCase
import com.peknight.commons.string.syntax.cases.to
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwk.KeyId
import com.peknight.jose.{JoseHeader, memberNameMap}
import io.circe.{Json, JsonObject}

case class JsonWebTokenHeader(
                               algorithm: Option[JsonWebAlgorithm] = None,
                               keyID: Option[KeyId] = None,
                               `type`: Option[String] = None,
                               contentType: Option[String] = None,
                               ext: Option[JsonObject] = None
                             ) extends JoseHeader
object JsonWebTokenHeader:
  given codecJsonWebTokenHeader[F[_], S](using
    Monad[F], ObjectType[S], ArrayType[S], NullType[S], StringType[S],
    Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JsonWebTokenHeader] =
    given CodecConfiguration = CodecConfiguration.default
      .withTransformMemberNames(memberName => memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
      .withExtendedField("ext")
    Codec.derived[F, S, JsonWebTokenHeader]

  given jsonCodecJsonWebTokenHeader[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebTokenHeader] =
    codecJsonWebTokenHeader[F, Json]

  given circeCodecJsonWebTokenHeader: io.circe.Codec[JsonWebTokenHeader] =
    codec[JsonWebTokenHeader]
end JsonWebTokenHeader
