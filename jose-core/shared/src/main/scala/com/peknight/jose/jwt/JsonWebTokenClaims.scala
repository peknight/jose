package com.peknight.jose.jwt

import cats.Monad
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.*
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.string.cases.SnakeCase
import com.peknight.commons.string.syntax.cases.to
import com.peknight.jose.jwx.ExtendedField
import io.circe.{Json, JsonObject}

import java.time.Instant

case class JsonWebTokenClaims(
                               issuer: Option[String] = None,
                               subject: Option[String] = None,
                               audience: Option[Set[String]] = None,
                               expirationTime: Option[Instant] = None,
                               notBefore: Option[Instant] = None,
                               issuedAt: Option[Instant] = None,
                               jwtID: Option[JwtId] = None,
                               ext: Option[JsonObject] = None
                             ) extends ExtendedField:
end JsonWebTokenClaims
object JsonWebTokenClaims:
  private val memberNameMap: Map[String, String] =
    Map(
      "issuer" -> "iss",
      "subject" -> "sub",
      "audience" -> "aud",
      "expirationTime" -> "exp",
      "notBefore" -> "nbf",
      "issuedAt" -> "iat",
      "jwtID" -> "jti",
    )

  given codecJsonWebTokenClaims[F[_], S](using
    monad: Monad[F],
    objectType: ObjectType[S],
    nullType: NullType[S],
    arrayType: ArrayType[S],
    numberType: NumberType[S],
    stringType: StringType[S],
    jsonObjectEncoder: Encoder[F, S, JsonObject],
    jsonObjectDecoder: Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JsonWebTokenClaims] =
    given CodecConfiguration = CodecConfiguration.default
      .withTransformMemberNames(memberName => memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
      .withExtendedField("ext")
    given Codec[F, S, Cursor[S], Instant] =
      Codec[F, S, Cursor[S], Instant](using
        Encoder[F, S, Long].contramap[Instant](_.getEpochSecond),
        Decoder[F, Cursor[S], Long].map[Instant](Instant.ofEpochSecond)
      )
    given Codec[F, S, Cursor[S], Set[String]] =
      Codec.cursor[F, S, Set[String]] { a =>
        if a.size == 1 then
          Encoder.encodeStringS[F, S].encode(a.head)
        else Encoder.encodeSetA[F, S, String].encode(a)
      } { t =>
        Decoder.decodeSetA[F, S, String].or(Decoder.decodeStringS[F, S].map[Set[String]](Set(_))).decode(t)
      }
    Codec.derived[F, S, JsonWebTokenClaims]

  given jsonCodecJsonWebTokenClaims[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebTokenClaims] =
    codecJsonWebTokenClaims[F, Json]

  given circeCodecJsonWebTokenClaims: io.circe.Codec[JsonWebTokenClaims] = codec[JsonWebTokenClaims]
end JsonWebTokenClaims
