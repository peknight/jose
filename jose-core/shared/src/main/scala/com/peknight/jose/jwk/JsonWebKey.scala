package com.peknight.jose.jwk

import cats.Monad
import cats.data.NonEmptyList
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.Decoder.decodeOptionAOU
import com.peknight.codec.base.{Base64, Base64Url}
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.http4s.instances.uri.given
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.{Codec, Decoder}
import com.peknight.commons.string.cases.SnakeCase
import com.peknight.commons.string.syntax.cases.to
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.KeyType.{EllipticCurve, OctetSequence, RSA}
import org.http4s.Uri

/**
 * https://datatracker.ietf.org/doc/html/rfc7517
 */
sealed trait JsonWebKey:
  def keyType: KeyType
  def publicKeyUse: Option[PublicKeyUseType]
  def keyOperations: Option[Seq[KeyOperationType]]
  def algorithm: Option[JsonWebAlgorithm]
  def keyID: Option[KeyId]
  def x509URL: Option[Uri]
  def x509CertificateChain: Option[NonEmptyList[Base64]]
  def x509CertificateSHA1Thumbprint: Option[Base64Url]
  def x509CertificateSHA256Thumbprint: Option[Base64Url]
end JsonWebKey
object JsonWebKey extends JsonWebKeyPlatform:
  private val memberNameMap: Map[String, String] =
    Map(
      "keyType" -> "kty",
      "publicKeyUse" -> "use",
      "keyOperations" -> "key_ops",
      "algorithm" -> "alg",
      "keyID" -> "kid",
      "x509URL" -> "x5u",
      "x509CertificateChain" -> "x5c",
      "x509CertificateSHA1Thumbprint" -> "x5t",
      "x509CertificateSHA256Thumbprint" -> "x5t#S256",

      // EC
      "curve" -> "crv",
      "xCoordinate" -> "x",
      "yCoordinate" -> "y",
      "eccPrivateKey" -> "d",

      // RSA
      "modulus" -> "n",
      "exponent" -> "e",
      "privateExponent" -> "d",
      "firstPrimeFactor" -> "p",
      "secondPrimeFactor" -> "q",
      "firstFactorCRTExponent" -> "dp",
      "secondFactorCRTExponent" -> "dq",
      "firstCRTCoefficient" -> "qi",
      "otherPrimesInfo" -> "oth",

      // oct
      "keyValue" -> "k",
    )

  private val constructorNameMap: Map[String, String] =
    Map(
      "EllipticCurveJsonWebKey" -> EllipticCurve.name,
      "RSAJsonWebKey" -> RSA.name,
      "OctetSequenceJsonWebKey" -> OctetSequence.name,
    )

  case class EllipticCurveJsonWebKey(
    curve: Curve,
    xCoordinate: Base64Url,
    yCoordinate: Base64Url,
    eccPrivateKey: Option[Base64Url],
    publicKeyUse: Option[PublicKeyUseType],
    keyOperations: Option[Seq[KeyOperationType]],
    algorithm: Option[JsonWebAlgorithm],
    keyID: Option[KeyId],
    x509URL: Option[Uri],
    x509CertificateChain: Option[NonEmptyList[Base64]],
    x509CertificateSHA1Thumbprint: Option[Base64Url],
    x509CertificateSHA256Thumbprint: Option[Base64Url]
  ) extends JsonWebKey:
    val keyType: KeyType = EllipticCurve
  end EllipticCurveJsonWebKey

  case class RSAJsonWebKey(
    modulus: Base64Url,
    exponent: Base64Url,
    privateExponent: Option[Base64Url],
    firstPrimeFactor: Option[Base64Url],
    secondPrimeFactor: Option[Base64Url],
    firstFactorCRTExponent: Option[Base64Url],
    secondFactorCRTExponent: Option[Base64Url],
    firstCRTCoefficient: Option[Base64Url],
    otherPrimesInfo: Option[Seq[OtherPrimesInfo]],
    publicKeyUse: Option[PublicKeyUseType],
    keyOperations: Option[Seq[KeyOperationType]],
    algorithm: Option[JsonWebAlgorithm],
    keyID: Option[KeyId],
    x509URL: Option[Uri],
    x509CertificateChain: Option[NonEmptyList[Base64]],
    x509CertificateSHA1Thumbprint: Option[Base64Url],
    x509CertificateSHA256Thumbprint: Option[Base64Url]
  ) extends JsonWebKey:
    val keyType: KeyType = RSA
  end RSAJsonWebKey

  case class OctetSequenceJsonWebKey(
    keyValue: Base64Url,
    publicKeyUse: Option[PublicKeyUseType],
    keyOperations: Option[Seq[KeyOperationType]],
    algorithm: Option[JsonWebAlgorithm],
    keyID: Option[KeyId],
    x509URL: Option[Uri],
    x509CertificateChain: Option[NonEmptyList[Base64]],
    x509CertificateSHA1Thumbprint: Option[Base64Url],
    x509CertificateSHA256Thumbprint: Option[Base64Url]
  ) extends JsonWebKey:
    val keyType: KeyType = OctetSequence
  end OctetSequenceJsonWebKey

  given codecJsonWebKey[F[_], S](using Monad[F], ObjectType[S], ArrayType[S], NullType[S], StringType[S])
  : Codec[F, S, Cursor[S], JsonWebKey] =
    given CodecConfiguration = CodecConfiguration.default
      .withTransformMemberNames(memberName => memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
      .withDiscriminator("kty")
      .withTransformConstructorNames(constructorNames => constructorNameMap.getOrElse(constructorNames, constructorNames))
    Codec.derived[F, S, JsonWebKey]

  given circeCodecJsonWebKey: io.circe.Codec[JsonWebKey] = codec[JsonWebKey]
end JsonWebKey
