package com.peknight.jose.jwt

import cats.syntax.functor.*
import cats.{Monad, Show}
import com.peknight.cats.instances.time.instant.given
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.*
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.string.cases.SnakeCase
import com.peknight.commons.string.syntax.cases.to
import com.peknight.commons.time.syntax.temporal.{minus, plus}
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.either.label
import com.peknight.jose.jwx.ExtendedField
import com.peknight.validation.collection.iterableOnce.either.{contains, interact}
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
                             ) extends ExtendedField:
  def expectedIssuers(expected: String*): Either[Error, Unit] =
    issuer.toRight(OptionEmpty).flatMap(issuer => contains(issuer, expected)).label("issuer").as(())
  def expectedSubjects(expected: String*): Either[Error, Unit] =
    subject.toRight(OptionEmpty).flatMap(subject => contains(subject, expected)).label("subject").as(())
  def acceptableAudiences(acceptable: String*): Either[Error, Unit] =
    audience.toRight(OptionEmpty).flatMap(audience => interact(audience, acceptable)).label("audience").as(())
  def requireExpirationTime: Either[Error, Unit] = expirationTime.toRight(OptionEmpty.label("expirationTime")).as(())
  def requireNotBefore: Either[Error, Unit] = notBefore.toRight(OptionEmpty.label("notBefore")).as(())
  def requireIssuedAt: Either[Error, Unit] = issuedAt.toRight(OptionEmpty.label("issuedAt")).as(())
  def requireJwtID: Either[Error, Unit] = jwtID.toRight(OptionEmpty.label("jwtID")).as(())
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
