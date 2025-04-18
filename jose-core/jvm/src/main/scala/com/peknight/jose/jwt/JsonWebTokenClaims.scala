package com.peknight.jose.jwt

import cats.syntax.functor.*
import cats.{Monad, Show}
import com.peknight.cats.instances.time.instant.given
import com.peknight.codec.circe.Ext
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.config.CodecConfig
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.instances.time.instant.codecInstantOfEpochSecondNS
import com.peknight.codec.sum.*
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.text.cases.SnakeCase
import com.peknight.commons.text.syntax.cases.to
import com.peknight.commons.time.syntax.temporal.{minus, plus}
import com.peknight.error.Error
import com.peknight.error.syntax.either.label
import com.peknight.validation.spire.math.interval.either.contains as intervalContains
import io.circe.{Json, JsonObject}
import spire.math.Interval

import java.time.Instant
import scala.concurrent.duration.{Duration, FiniteDuration}

case class JsonWebTokenClaims(
                               issuer: Option[String] = None,
                               subject: Option[String] = None,
                               audience: Option[Set[String]] = None,
                               expirationTime: Option[Instant] = None,
                               notBefore: Option[Instant] = None,
                               issuedAt: Option[Instant] = None,
                               jwtID: Option[JwtId] = None,
                               ext: JsonObject = JsonObject.empty
                             ) extends Ext with JsonWebTokenClaimsPlatform derives CanEqual:
  def toInterval(allowedClockSkew: FiniteDuration = Duration.Zero): Interval[Instant] =
    (expirationTime, notBefore) match
      case (Some(expirationTime), Some(notBefore)) =>
        Interval.openUpper(notBefore.minus(allowedClockSkew), expirationTime.plus(allowedClockSkew))
      case (Some(expirationTime), None) => Interval.below(expirationTime.plus(allowedClockSkew))
      case (None, Some(notBefore)) => Interval.atOrAbove(notBefore.minus(allowedClockSkew))
      case _ => Interval.all
  def checkTime(evaluationTime: Instant, allowedClockSkew: FiniteDuration = Duration.Zero): Either[Error, Unit] =
    given Show[Instant] = Show.fromToString[Instant]
    intervalContains(evaluationTime, toInterval(allowedClockSkew)).label("evaluationTime").as(())
end JsonWebTokenClaims
object JsonWebTokenClaims extends JsonWebTokenClaimsCompanion:
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
    given CodecConfig = CodecConfig.default
      .withTransformMemberName(memberName => memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
      .withExtField("ext")
    given Codec[F, S, Cursor[S], Instant] = codecInstantOfEpochSecondNS[F, S]
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
