package com.peknight.jose.jwk

import cats.data.NonEmptyList
import cats.{Applicative, Monad, Show}
import com.peknight.codec.base.{Base64, Base64UrlNoPad}
import com.peknight.codec.circe.Ext
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.config.CodecConfig
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.DecodingFailure
import com.peknight.codec.http4s.instances.uri.given
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.text.cases.SnakeCase
import com.peknight.commons.text.syntax.cases.to
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.KeyType.{EllipticCurve, OctetKeyPair, OctetSequence, RSA}
import com.peknight.jose.jwx.encodeToJson
import com.peknight.security.key.agreement.{X25519, X448}
import com.peknight.security.signature.{Ed25519, Ed448}
import com.peknight.security.spec.NamedParameterSpecName
import io.circe.{Json, JsonObject}
import org.http4s.Uri

/**
 * https://datatracker.ietf.org/doc/html/rfc7517
 */
sealed trait JsonWebKey extends Ext with JsonWebKeyPlatform:
  def keyType: KeyType
  def publicKeyUse: Option[PublicKeyUseType]
  def keyOperations: Option[Seq[KeyOperationType]]
  def algorithm: Option[JsonWebAlgorithm]
  def keyID: Option[KeyId]
  def x509URL: Option[Uri]
  def x509CertificateChain: Option[NonEmptyList[Base64]]
  def x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad]
  def x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad]
  def excludePrivate: JsonWebKey
  def thumbprintHashInput: String
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

  sealed trait AsymmetricJsonWebKey extends JsonWebKey with AsymmetricJsonWebKeyPlatform

  case class EllipticCurveJsonWebKey(
    curve: Curve,
    xCoordinate: Base64UrlNoPad,
    yCoordinate: Base64UrlNoPad,
    eccPrivateKey: Option[Base64UrlNoPad] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
    ext: JsonObject = JsonObject.empty
  ) extends AsymmetricJsonWebKey with EllipticCurveJsonWebKeyPlatform:
    val keyType: KeyType = EllipticCurve
    def excludePrivate: EllipticCurveJsonWebKey = copy(eccPrivateKey = None)
    def thumbprintHashInput: String =
      s"""{"crv":"${curve.name}","kty":"${keyType.name}","x":"${xCoordinate.value}","y":"${yCoordinate.value}"}"""
  end EllipticCurveJsonWebKey

  case class RSAJsonWebKey(
    modulus: Base64UrlNoPad,
    exponent: Base64UrlNoPad,
    privateExponent: Option[Base64UrlNoPad] = None,
    firstPrimeFactor: Option[Base64UrlNoPad] = None,
    secondPrimeFactor: Option[Base64UrlNoPad] = None,
    firstFactorCRTExponent: Option[Base64UrlNoPad] = None,
    secondFactorCRTExponent: Option[Base64UrlNoPad] = None,
    firstCRTCoefficient: Option[Base64UrlNoPad] = None,
    otherPrimesInfo: Option[Seq[OtherPrimesInfo]] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
    ext: JsonObject = JsonObject.empty
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
    def thumbprintHashInput: String =
      s"""{"e":"${exponent.value}","kty":"${keyType.name}","n":"${modulus.value}"}"""
  end RSAJsonWebKey

  case class OctetSequenceJsonWebKey(
    keyValue: Base64UrlNoPad,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
    ext: JsonObject = JsonObject.empty
  ) extends JsonWebKey with OctetSequenceJsonWebKeyPlatform:
    val keyType: KeyType = OctetSequence
    def excludePrivate: JsonWebKey = this
    def thumbprintHashInput: String =
      s"""{"k":"${keyValue.value}","kty":"${keyType.name}"}"""
  end OctetSequenceJsonWebKey

  case class OctetKeyPairJsonWebKey(
    curve: NamedParameterSpecName,
    xCoordinate: Base64UrlNoPad,
    eccPrivateKey: Option[Base64UrlNoPad] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
    ext: JsonObject = JsonObject.empty
  ) extends AsymmetricJsonWebKey with OctetKeyPairJsonWebKeyPlatform:
    val keyType: KeyType = OctetKeyPair
    def excludePrivate: OctetKeyPairJsonWebKey = copy(eccPrivateKey = None)
    def thumbprintHashInput: String =
      s"""{"crv":"${curve.parameterSpecName}","kty":"${keyType.name}","x":"${xCoordinate.value}"}"""
  end OctetKeyPairJsonWebKey

  given stringDecodeBase64UrlNoPad[F[_]: Applicative]: Decoder[F, String, Base64UrlNoPad] =
    Decoder.applicative[F, String, Base64UrlNoPad](t =>
      Base64UrlNoPad.baseParser.parseAll(t.replaceAll("\\+", "-").replaceAll("/", "_").replaceAll("=*+$", ""))
        .left.map(DecodingFailure.apply)
    )

  given decodeBase64UrlNoPad[F[_]: Applicative, S: {StringType, Show}]: Decoder[F, Cursor[S], Base64UrlNoPad] =
    Decoder.decodeS[F, S, Base64UrlNoPad]

  private[jwk] val jsonWebKeyCodecConfig: CodecConfig =
    CodecConfig.default
      .withTransformMemberName(memberName => memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
      .withTransformConstructorName(constructorNames => constructorNameMap.getOrElse(constructorNames, constructorNames))
      .withDiscriminator("kty")
      .withExtField("ext")

  given codecEllipticCurveJsonWebKey[F[_], S](using Monad[F], ObjectType[S], NullType[S], ArrayType[S], StringType[S],
                                              Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject], Show[S])
  : Codec[F, S, Cursor[S], EllipticCurveJsonWebKey] =
    given CodecConfig = jsonWebKeyCodecConfig
    Codec.derived[F, S, EllipticCurveJsonWebKey]

  given jsonCodecEllipticCurveJsonWebKey[F[_] : Monad]: Codec[F, Json, Cursor[Json], EllipticCurveJsonWebKey] =
    codecEllipticCurveJsonWebKey[F, Json]

  given circeCodecEllipticCurveJsonWebKey: io.circe.Codec[EllipticCurveJsonWebKey] = codec[EllipticCurveJsonWebKey]

  given showEllipticCurveJsonWebKey: Show[EllipticCurveJsonWebKey] = Show.show[EllipticCurveJsonWebKey](encodeToJson)

  given codecRSAJsonWebKey[F[_], S](using Monad[F], ObjectType[S], NullType[S], ArrayType[S], StringType[S],
                                    Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject], Show[S])
  : Codec[F, S, Cursor[S], RSAJsonWebKey] =
    given CodecConfig = jsonWebKeyCodecConfig
    Codec.derived[F, S, RSAJsonWebKey]

  given jsonCodecRSAJsonWebKey[F[_] : Monad]: Codec[F, Json, Cursor[Json], RSAJsonWebKey] =
    codecRSAJsonWebKey[F, Json]

  given circeCodecRSAJsonWebKey: io.circe.Codec[RSAJsonWebKey] = codec[RSAJsonWebKey]

  given showRSAJsonWebKey: Show[RSAJsonWebKey] = Show.show[RSAJsonWebKey](encodeToJson)

  given stringCodecNamedParameterSpecName[F[_] : Applicative]: Codec[F, String, String, NamedParameterSpecName] =
    Codec.mapOption[F, String, String, NamedParameterSpecName](_.parameterSpecName)(
      t => List(X25519, X448, Ed25519, Ed448).find(_.parameterSpecName == t)
    )

  given codecNamedParameterSpecName[F[_] : Applicative, S: {StringType, Show}]: Codec[F, S, Cursor[S], NamedParameterSpecName] =
    Codec.codecS[F, S, NamedParameterSpecName]

  given codecOctetKeyPairJsonWebKey[F[_], S](using Monad[F], ObjectType[S], NullType[S], ArrayType[S], StringType[S],
                                             Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject], Show[S])
  : Codec[F, S, Cursor[S], OctetKeyPairJsonWebKey] =
    given CodecConfig = jsonWebKeyCodecConfig
    Codec.derived[F, S, OctetKeyPairJsonWebKey]

  given jsonCodecOctetKeyPairJsonWebKey[F[_] : Monad]: Codec[F, Json, Cursor[Json], OctetKeyPairJsonWebKey] =
    codecOctetKeyPairJsonWebKey[F, Json]

  given circeCodecOctetKeyPairJsonWebKey: io.circe.Codec[OctetKeyPairJsonWebKey] = codec[OctetKeyPairJsonWebKey]

  given showOctetKeyPairJsonWebKey: Show[OctetKeyPairJsonWebKey] = Show.show[OctetKeyPairJsonWebKey](encodeToJson)

  given codecAsymmetricJsonWebKey[F[_], S](using Monad[F], ObjectType[S], NullType[S], ArrayType[S], StringType[S],
                                           Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject], Show[S])
  : Codec[F, S, Cursor[S], AsymmetricJsonWebKey] =
    given CodecConfig = jsonWebKeyCodecConfig
    Codec.derived[F, S, AsymmetricJsonWebKey]

  given jsonCodecAsymmetricJsonWebKey[F[_] : Monad]: Codec[F, Json, Cursor[Json], AsymmetricJsonWebKey] =
    codecAsymmetricJsonWebKey[F, Json]

  given circeCodecAsymmetricJsonWebKey: io.circe.Codec[AsymmetricJsonWebKey] = codec[AsymmetricJsonWebKey]

  given showAsymmetricJsonWebKey: Show[AsymmetricJsonWebKey] = Show.show[AsymmetricJsonWebKey](encodeToJson)

  given codecOctetSequenceJsonWebKey[F[_], S](using Monad[F], ObjectType[S], NullType[S], ArrayType[S], StringType[S],
                                              Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject], Show[S])
  : Codec[F, S, Cursor[S], OctetSequenceJsonWebKey] =
    given CodecConfig = jsonWebKeyCodecConfig
    Codec.derived[F, S, OctetSequenceJsonWebKey]

  given jsonCodecOctetSequenceJsonWebKey[F[_] : Monad]: Codec[F, Json, Cursor[Json], OctetSequenceJsonWebKey] =
    codecOctetSequenceJsonWebKey[F, Json]

  given circeCodecOctetSequenceJsonWebKey: io.circe.Codec[OctetSequenceJsonWebKey] = codec[OctetSequenceJsonWebKey]

  given showOctetSequenceJsonWebKey: Show[OctetSequenceJsonWebKey] = Show.show[OctetSequenceJsonWebKey](encodeToJson)

  given codecJsonWebKey[F[_], S](using Monad[F], ObjectType[S], NullType[S], ArrayType[S], StringType[S],
                                 Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject], Show[S])
  : Codec[F, S, Cursor[S], JsonWebKey] =
    given CodecConfig = jsonWebKeyCodecConfig
    Codec.derived[F, S, JsonWebKey]

  given jsonCodecJsonWebKey[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebKey] =
    codecJsonWebKey[F, Json]

  given circeCodecJsonWebKey: io.circe.Codec[JsonWebKey] = codec[JsonWebKey]

  given showJsonWebKey: Show[JsonWebKey] = Show.show[JsonWebKey](encodeToJson)
end JsonWebKey
