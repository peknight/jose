package com.peknight.jose.jwk

import cats.data.NonEmptyList
import cats.{Applicative, Monad}
import com.peknight.codec.Decoder.decodeOptionAOU
import com.peknight.codec.base.{Base64NoPad, Base64UrlNoPad}
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.http4s.instances.uri.given
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.{Codec, Decoder}
import com.peknight.commons.string.cases.SnakeCase
import com.peknight.commons.string.syntax.cases.to
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.KeyType.{EllipticCurve, OctetKeyPair, OctetSequence, RSA}
import com.peknight.security.algorithm.Algorithm
import com.peknight.security.spec.NamedParameterSpecName
import io.circe.Json
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
  def x509CertificateChain: Option[NonEmptyList[Base64NoPad]]
  def x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad]
  def x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad]
end JsonWebKey
object JsonWebKey extends JsonWebKeyCompanion:
  private val memberNameMap: Map[String, String] = com.peknight.jose.memberNameMap ++ Map(
    "keyType" -> "kty",
    "publicKeyUse" -> "use",
    "keyOperations" -> "key_ops",

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
      "OctetKeyPairJsonWebKey" -> OctetKeyPair.name,
    )

  sealed trait AsymmetricJsonWebKey extends JsonWebKey with AsymmetricJsonWebKeyPlatform:
    def excludePrivate: AsymmetricJsonWebKey
  end AsymmetricJsonWebKey

  case class EllipticCurveJsonWebKey(
    curve: Curve,
    xCoordinate: Base64UrlNoPad,
    yCoordinate: Base64UrlNoPad,
    eccPrivateKey: Option[Base64UrlNoPad],
    publicKeyUse: Option[PublicKeyUseType],
    keyOperations: Option[Seq[KeyOperationType]],
    algorithm: Option[JsonWebAlgorithm],
    keyID: Option[KeyId],
    x509URL: Option[Uri],
    x509CertificateChain: Option[NonEmptyList[Base64NoPad]],
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad],
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad]
  ) extends AsymmetricJsonWebKey with EllipticCurveJsonWebKeyPlatform:
    val keyType: KeyType = EllipticCurve
    def excludePrivate: EllipticCurveJsonWebKey = copy(eccPrivateKey = None)
  end EllipticCurveJsonWebKey

  case class RSAJsonWebKey(
    modulus: Base64UrlNoPad,
    exponent: Base64UrlNoPad,
    privateExponent: Option[Base64UrlNoPad],
    firstPrimeFactor: Option[Base64UrlNoPad],
    secondPrimeFactor: Option[Base64UrlNoPad],
    firstFactorCRTExponent: Option[Base64UrlNoPad],
    secondFactorCRTExponent: Option[Base64UrlNoPad],
    firstCRTCoefficient: Option[Base64UrlNoPad],
    otherPrimesInfo: Option[Seq[OtherPrimesInfo]],
    publicKeyUse: Option[PublicKeyUseType],
    keyOperations: Option[Seq[KeyOperationType]],
    algorithm: Option[JsonWebAlgorithm],
    keyID: Option[KeyId],
    x509URL: Option[Uri],
    x509CertificateChain: Option[NonEmptyList[Base64NoPad]],
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad],
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad]
  ) extends AsymmetricJsonWebKey with RSAJsonWebKeyPlatform:
    val keyType: KeyType = RSA
    def excludePrivate: RSAJsonWebKey = copy(
      privateExponent = None,
      firstPrimeFactor = None,
      secondPrimeFactor = None,
      firstFactorCRTExponent = None,
      secondFactorCRTExponent = None,
      firstCRTCoefficient = None
    )
  end RSAJsonWebKey

  case class OctetSequenceJsonWebKey(
    keyValue: Base64UrlNoPad,
    publicKeyUse: Option[PublicKeyUseType],
    keyOperations: Option[Seq[KeyOperationType]],
    algorithm: Option[JsonWebAlgorithm],
    keyID: Option[KeyId],
    x509URL: Option[Uri],
    x509CertificateChain: Option[NonEmptyList[Base64NoPad]],
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad],
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad]
  ) extends JsonWebKey with OctetSequenceJsonWebKeyPlatform:
    val keyType: KeyType = OctetSequence
  end OctetSequenceJsonWebKey

  sealed trait OctetKeyPairAlgorithm extends Algorithm with NamedParameterSpecName
  sealed trait XDH extends OctetKeyPairAlgorithm with com.peknight.security.key.agreement.XDH
  case object X25519 extends XDH with com.peknight.security.key.agreement.X25519
  case object X448 extends XDH with com.peknight.security.key.agreement.X448
  sealed trait EdDSA extends OctetKeyPairAlgorithm with com.peknight.security.signature.EdDSA
  case object Ed25519 extends EdDSA with com.peknight.security.signature.Ed25519
  case object Ed448 extends EdDSA with com.peknight.security.signature.Ed448

  given stringCodecOctetKeyPairAlgorithm[F[_]: Applicative]: Codec[F, String, String, OctetKeyPairAlgorithm] =
    Codec.mapOption[F, String, String, OctetKeyPairAlgorithm](_.algorithm)(
      t => List(X25519, X448, Ed25519, Ed448).find(_.algorithm == t)
    )

  given codecOctetKeyPairAlgorithm[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], OctetKeyPairAlgorithm] =
    Codec.codecS[F, S, OctetKeyPairAlgorithm]

  case class OctetKeyPairJsonWebKey(
    curve: OctetKeyPairAlgorithm,
    xCoordinate: Base64UrlNoPad,
    eccPrivateKey: Option[Base64UrlNoPad],
    publicKeyUse: Option[PublicKeyUseType],
    keyOperations: Option[Seq[KeyOperationType]],
    algorithm: Option[JsonWebAlgorithm],
    keyID: Option[KeyId],
    x509URL: Option[Uri],
    x509CertificateChain: Option[NonEmptyList[Base64NoPad]],
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad],
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad]
  ) extends AsymmetricJsonWebKey with OctetKeyPairJsonWebKeyPlatform:
    val keyType: KeyType = OctetKeyPair
    def excludePrivate: OctetKeyPairJsonWebKey = copy(eccPrivateKey = None)
  end OctetKeyPairJsonWebKey

  given codecJsonWebKey[F[_], S](using Monad[F], ObjectType[S], ArrayType[S], NullType[S], StringType[S])
  : Codec[F, S, Cursor[S], JsonWebKey] =
    given CodecConfiguration = CodecConfiguration.default
      .withTransformMemberNames(memberName => memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
      .withDiscriminator("kty")
      .withTransformConstructorNames(constructorNames => constructorNameMap.getOrElse(constructorNames, constructorNames))
    Codec.derived[F, S, JsonWebKey]

  given jsonCodecJsonWebKey[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebKey] =
    codecJsonWebKey[F, Json]

  given circeCodecJsonWebKey: io.circe.Codec[JsonWebKey] = codec[JsonWebKey]
end JsonWebKey
