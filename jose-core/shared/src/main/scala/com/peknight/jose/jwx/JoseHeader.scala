package com.peknight.jose.jwx

import cats.data.NonEmptyList
import cats.syntax.either.*
import cats.syntax.eq.*
import cats.syntax.functor.*
import cats.syntax.traverse.*
import cats.{Id, Monad}
import com.peknight.codec.base.{Base64NoPad, Base64UrlNoPad}
import com.peknight.codec.circe.Ext
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.http4s.instances.uri.given
import com.peknight.codec.sum.*
import com.peknight.codec.syntax.encoder.asS
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.string.cases.SnakeCase
import com.peknight.commons.string.syntax.cases.to
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.either.{asError, label}
import com.peknight.jose.error.{InvalidMediaType, UnrecognizedCriticalHeader}
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.compression.CompressionAlgorithm
import com.peknight.jose.jwa.encryption.EncryptionAlgorithm
import com.peknight.jose.jwa.signature.none
import com.peknight.jose.jwk.{JsonWebKey, KeyId}
import com.peknight.jose.{base64UrlEncodePayloadLabel, memberNameMap}
import com.peknight.security.cipher.{Asymmetric, Symmetric}
import com.peknight.validation.std.either.isTrue
import io.circe.{Json, JsonObject}
import org.http4s.{MediaType, Uri}

case class JoseHeader(
                       algorithm: Option[JsonWebAlgorithm] = None,
                       encryptionAlgorithm: Option[EncryptionAlgorithm] = None,
                       compressionAlgorithm: Option[CompressionAlgorithm] = None,
                       jwkSetURL: Option[Uri] = None,
                       jwk: Option[JsonWebKey] = None,
                       keyID: Option[KeyId] = None,
                       x509URL: Option[Uri] = None,
                       x509CertificateChain: Option[NonEmptyList[Base64NoPad]] = None,
                       x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
                       x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
                       `type`: Option[String] = None,
                       contentType: Option[String] = None,
                       critical: Option[List[String]] = None,
                       ephemeralPublicKey: Option[JsonWebKey] = None,
                       agreementPartyUInfo: Option[Base64UrlNoPad] = None,
                       agreementPartyVInfo: Option[Base64UrlNoPad] = None,
                       initializationVector: Option[Base64UrlNoPad] = None,
                       authenticationTag: Option[Base64UrlNoPad] = None,
                       pbes2SaltInput: Option[Base64UrlNoPad] = None,
                       pbes2Count: Option[Long] = None,
                       // rfc7797
                       base64UrlEncodePayload: Option[Boolean] = None,
                       ext: JsonObject = JsonObject.empty
                     ) extends Ext:
  def isBase64UrlEncodePayload: Boolean = base64UrlEncodePayload.getOrElse(true)
  def base64UrlEncodePayload(b64: Boolean): JoseHeader =
    if b64 then
      copy(critical = removeCritical(base64UrlEncodePayloadLabel), base64UrlEncodePayload = None)
    else
      copy(critical = addCritical(base64UrlEncodePayloadLabel), base64UrlEncodePayload = Some(false))
  end base64UrlEncodePayload

  def addExt(label: String, value: Json): JoseHeader =
    copy(critical = addCritical(label), ext = ext.add(label, value))

  def removeExt(label: String): JoseHeader =
    copy(critical = removeCritical(label), ext = ext.remove(label))

  def checkCritical(knownCriticalHeaders: List[String]): Either[UnrecognizedCriticalHeader, Unit] =
    critical match
      case Some(critical) =>
        critical.traverse(header => isTrue(knownCriticalHeaders.contains(header), UnrecognizedCriticalHeader(header)))
          .as(())
      case None => ().asRight

  private def addCritical(label: String): Option[List[String]] =
    Some(critical.map(crit => if crit.contains(label) then crit else crit :+ label).getOrElse(List(label)))

  private def removeCritical(label: String): Option[List[String]] =
    critical.map(_.filterNot(_ == label)).filterNot(_.isEmpty)

  def isNoneAlgorithm: Boolean = algorithm.forall(_ == none)
  def isSymmetric: Boolean = algorithm.exists(_.isInstanceOf[Symmetric])
  def isAsymmetric: Boolean = algorithm.exists(_.isInstanceOf[Asymmetric])
  def isNestedJsonWebToken: Boolean =
    contentType.exists(cty => "jwt".equalsIgnoreCase(cty) || "application/jwt".equalsIgnoreCase(cty))

  def deepMerge(that: JoseHeader): JoseHeader =
    JoseHeader(
      that.algorithm.orElse(this.algorithm),
      that.encryptionAlgorithm.orElse(this.encryptionAlgorithm),
      that.compressionAlgorithm.orElse(this.compressionAlgorithm),
      that.jwkSetURL.orElse(this.jwkSetURL),
      that.jwk.orElse(this.jwk),
      that.keyID.orElse(this.keyID),
      that.x509URL.orElse(this.x509URL),
      that.x509CertificateChain.orElse(this.x509CertificateChain),
      that.x509CertificateSHA1Thumbprint.orElse(this.x509CertificateSHA1Thumbprint),
      that.x509CertificateSHA256Thumbprint.orElse(this.x509CertificateSHA256Thumbprint),
      that.`type`.orElse(this.`type`),
      that.contentType.orElse(this.contentType),
      Option((this.critical.getOrElse(Nil) ::: that.critical.getOrElse(Nil)).distinct).filter(_.nonEmpty),
      that.ephemeralPublicKey.orElse(this.ephemeralPublicKey),
      that.agreementPartyUInfo.orElse(this.agreementPartyUInfo),
      that.agreementPartyVInfo.orElse(this.agreementPartyVInfo),
      that.initializationVector.orElse(this.initializationVector),
      that.authenticationTag.orElse(this.authenticationTag),
      that.pbes2SaltInput.orElse(this.pbes2SaltInput),
      that.pbes2Count.orElse(this.pbes2Count),
      that.base64UrlEncodePayload.orElse(this.base64UrlEncodePayload),
      this.ext.deepMerge(that.ext)
    )
  def toMediaType: Either[Error, Option[MediaType]] =
    `type`.fold(Right(None))(typ => JoseHeader.toMediaType(typ).map(Some.apply))

  def requireType: Either[Error, Unit] = `type`.toRight(OptionEmpty.label("type")).as(())

  def expectedType(expected: String, requireType: Boolean = false): Either[Error, Unit] =
    `type` match
      case None => if requireType then OptionEmpty.label("type").asLeft else ().asRight
      case Some(value) =>
        val either =
          for
            typ <- `type`.toRight(OptionEmpty)
            typ <- JoseHeader.toMediaType(typ)
            exp <- JoseHeader.toMediaType(expected)
            _ <- isTrue(typ.mainType === exp.mainType, InvalidMediaType(typ, exp))
            _ <- isTrue(typ.subType === "*" || typ.subType === exp.subType, InvalidMediaType(typ, exp))
          yield
            ()
        either.label("type")
  end expectedType
end JoseHeader
object JoseHeader:
  def withExt[A](ext: A, algorithm: Option[JsonWebAlgorithm] = None,
                 encryptionAlgorithm: Option[EncryptionAlgorithm] = None,
                 compressionAlgorithm: Option[CompressionAlgorithm] = None,
                 jwkSetURL: Option[Uri] = None,
                 jwk: Option[JsonWebKey] = None,
                 keyID: Option[KeyId] = None,
                 x509URL: Option[Uri] = None,
                 x509CertificateChain: Option[NonEmptyList[Base64NoPad]] = None,
                 x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
                 x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
                 `type`: Option[String] = None,
                 contentType: Option[String] = None,
                 critical: Option[List[String]] = None,
                 ephemeralPublicKey: Option[JsonWebKey] = None,
                 agreementPartyUInfo: Option[Base64UrlNoPad] = None,
                 agreementPartyVInfo: Option[Base64UrlNoPad] = None,
                 initializationVector: Option[Base64UrlNoPad] = None,
                 authenticationTag: Option[Base64UrlNoPad] = None,
                 pbes2SaltInput: Option[Base64UrlNoPad] = None,
                 pbes2Count: Option[Long] = None,
                 base64UrlEncodePayload: Option[Boolean] = None
                )(using Encoder[Id, Json, A]): JoseHeader =
    JoseHeader(algorithm, encryptionAlgorithm, compressionAlgorithm, jwkSetURL, jwk, keyID, x509URL,
      x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint, `type`, contentType,
      critical, ephemeralPublicKey, agreementPartyUInfo, agreementPartyVInfo, initializationVector, authenticationTag,
      pbes2SaltInput, pbes2Count, base64UrlEncodePayload, ext.asS[Id, Json].asObject.getOrElse(JsonObject.empty))

  given codecJoseHeader[F[_], S](using
    Monad[F], ObjectType[S], NullType[S], ArrayType[S], BooleanType[S], NumberType[S], StringType[S],
    Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JoseHeader] =
    given CodecConfiguration = CodecConfiguration.default
      .withTransformMemberNames(memberName => memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
      .withExtField("ext")
    Codec.derived[F, S, JoseHeader]

  given jsonCodecJoseHeader[F[_]: Monad]: Codec[F, Json, Cursor[Json], JoseHeader] = codecJoseHeader[F, Json]

  given circeCodecJoseHeader: io.circe.Codec[JoseHeader] = codec[JoseHeader]

  def toMediaType(`type`: String): Either[Error, MediaType] =
    MediaType.parse(if `type`.contains("/") then `type` else s"application/${`type`}").asError
end JoseHeader
