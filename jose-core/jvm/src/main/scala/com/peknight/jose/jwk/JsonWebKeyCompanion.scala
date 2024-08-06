package com.peknight.jose.jwk

import cats.data.NonEmptyList
import cats.syntax.either.*
import cats.syntax.option.*
import com.peknight.codec.base.{Base64, Base64Url}
import com.peknight.jose.error.*
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.JsonWebKey.*
import com.peknight.security.algorithm.Algorithm
import com.peknight.security.key.agreement.XDH
import com.peknight.security.signature.EdDSA
import org.http4s.Uri
import scodec.bits.ByteVector

import java.math.BigInteger
import java.security.interfaces.*
import java.security.spec.{EllipticCurve, NamedParameterSpec}
import java.security.{Key, PrivateKey, PublicKey}
import java.util.Optional
import scala.jdk.OptionConverters.*
import scala.reflect.ClassTag

trait JsonWebKeyCompanion:

  def fromKey(
    key: Key,
    otherPrimesInfo: Option[Seq[OtherPrimesInfo]] = None,
    curve: Option[Curve] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64Url] = None,
    x509CertificateSHA256Thumbprint: Option[Base64Url] = None
  ): Either[JsonWebKeyCreationError, JsonWebKey] =
    key match
      case publicKey: PublicKey =>
        fromKeyPair(publicKey, None, otherPrimesInfo, curve, publicKeyUse, keyOperations, algorithm, keyID, x509URL,
          x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint)
      case privateKey: PrivateKey => UnsupportedKey(privateKey.getAlgorithm)(using ClassTag(privateKey.getClass)).asLeft
      case k =>
        fromOctetSequenceKey(k, publicKeyUse, keyOperations, algorithm, keyID, x509URL, x509CertificateChain,
          x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
        ).asRight

  def fromKeyPair(
    publicKey: PublicKey,
    privateKey: Option[PrivateKey] = None,
    otherPrimesInfo: Option[Seq[OtherPrimesInfo]] = None,
    curve: Option[Curve] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64Url] = None,
    x509CertificateSHA256Thumbprint: Option[Base64Url] = None
  ): Either[JsonWebKeyCreationError, JsonWebKey] =
    publicKey match
      case rsaPublicKey: RSAPublicKey =>
        privateKey match
          case Some(rsaPrivateKey: RSAPrivateKey) =>
            fromRSAKey(rsaPublicKey, Some(rsaPrivateKey), otherPrimesInfo, publicKeyUse, keyOperations, algorithm,
              keyID, x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
            ).asRight[JsonWebKeyCreationError]
          case Some(privKey) => MismatchedKeyPair[RSAPrivateKey].asLeft
          case None =>
            fromRSAKey(rsaPublicKey, None, otherPrimesInfo, publicKeyUse, keyOperations, algorithm,
              keyID, x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
            ).asRight[JsonWebKeyCreationError]
      case ecPublicKey: ECPublicKey =>
        privateKey match
          case Some(ecPrivateKey: ECPrivateKey) =>
            fromEllipticCurveKey(ecPublicKey, Some(ecPrivateKey), curve, publicKeyUse, keyOperations, algorithm, keyID,
              x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
            )
          case Some(privKey) => MismatchedKeyPair[ECPrivateKey].asLeft
          case None =>
            fromEllipticCurveKey(ecPublicKey, None, curve, publicKeyUse, keyOperations, algorithm, keyID,
              x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
            )
      case pubKey if applicableKeyAlgorithms.exists(algorithm => algorithm.algorithm == pubKey.getAlgorithm) =>
        fromOctetKeyPairKey(pubKey, privateKey, publicKeyUse, keyOperations, algorithm, keyID, x509URL,
          x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
        )
      case pubKey => UnsupportedKey(pubKey.getAlgorithm)(using ClassTag(pubKey.getClass)).asLeft

  def fromRSAKey(
    rsaPublicKey: RSAPublicKey,
    rsaPrivateKey: Option[RSAPrivateKey] = None,
    otherPrimesInfo: Option[Seq[OtherPrimesInfo]] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64Url] = None,
    x509CertificateSHA256Thumbprint: Option[Base64Url] = None
  ): RSAJsonWebKey =
    def mapCrt(f: RSAPrivateCrtKey => BigInteger): Option[Base64Url] =
      rsaPrivateKey.flatMap {
        case d: RSAPrivateCrtKey => Some(Base64Url.fromBigInt(BigInt(f(d))))
        case _ => None
      }
    RSAJsonWebKey(
      Base64Url.fromBigInt(BigInt(rsaPublicKey.getModulus)),
      Base64Url.fromBigInt(BigInt(rsaPublicKey.getPublicExponent)),
      rsaPrivateKey.map(d => Base64Url.fromBigInt(BigInt(d.getPrivateExponent))),
      mapCrt(_.getPrimeP),
      mapCrt(_.getPrimeQ),
      mapCrt(_.getPrimeExponentP),
      mapCrt(_.getPrimeExponentQ),
      mapCrt(_.getCrtCoefficient),
      otherPrimesInfo,
      publicKeyUse,
      keyOperations,
      algorithm,
      keyID,
      x509URL,
      x509CertificateChain,
      x509CertificateSHA1Thumbprint,
      x509CertificateSHA256Thumbprint
    )

  def fromEllipticCurveKey(
    ecPublicKey: ECPublicKey,
    ecPrivateKey: Option[ECPrivateKey] = None,
    curve: Option[Curve] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64Url] = None,
    x509CertificateSHA256Thumbprint: Option[Base64Url] = None
  ): Either[JsonWebKeyCreationError, EllipticCurveJsonWebKey] =
    val ellipticCurve: EllipticCurve = ecPublicKey.getParams.getCurve
    for
      curve <- Curve.curveMap.get(ellipticCurve).orElse(curve).toRight[JsonWebKeyCreationError](NoSuchCurve)
      fieldSize = ellipticCurve.getField.getFieldSize
      xCoordinate = encodeCoordinate(BigInt(ecPublicKey.getW.getAffineX), fieldSize)
      yCoordinate = encodeCoordinate(BigInt(ecPublicKey.getW.getAffineY), fieldSize)
      eccPrivateKey = ecPrivateKey.map(pk => encodeCoordinate(BigInt(pk.getS), fieldSize))
    yield
      EllipticCurveJsonWebKey(
        curve,
        xCoordinate,
        yCoordinate,
        eccPrivateKey,
        publicKeyUse,
        keyOperations,
        algorithm,
        keyID,
        x509URL,
        x509CertificateChain,
        x509CertificateSHA1Thumbprint,
        x509CertificateSHA256Thumbprint
      )

  def fromOctetKeyPairKey(
    publicKey: PublicKey,
    privateKey: Option[PrivateKey] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64Url] = None,
    x509CertificateSHA256Thumbprint: Option[Base64Url] = None
  ): Either[JsonWebKeyCreationError, OctetKeyPairJsonWebKey] =
    for
      tuple <- octetKeyPairSubType(publicKey, privateKey)
    yield
      OctetKeyPairJsonWebKey(
        tuple._1,
        tuple._2,
        tuple._3,
        publicKeyUse,
        keyOperations,
        algorithm,
        keyID,
        x509URL,
        x509CertificateChain,
        x509CertificateSHA1Thumbprint,
        x509CertificateSHA256Thumbprint
      )

  def fromOctetSequenceKey(
    key: Key,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64Url] = None,
    x509CertificateSHA256Thumbprint: Option[Base64Url] = None
  ): OctetSequenceJsonWebKey =
    OctetSequenceJsonWebKey(
      Base64Url.fromByteVector(ByteVector(key.getEncoded)),
      publicKeyUse,
      keyOperations,
      algorithm,
      keyID,
      x509URL,
      x509CertificateChain,
      x509CertificateSHA1Thumbprint,
      x509CertificateSHA256Thumbprint
    )

  private def encodeCoordinate(coordinate: BigInt, fieldSize: Int): Base64Url =
    val notPadded = toByteVectorUnsigned(coordinate)
    val bytesToOutput = (fieldSize + 7) / 8
    val bytes =
      if notPadded.length >= bytesToOutput then notPadded
      else ByteVector.fill(bytesToOutput - notPadded.length)(0) ++ notPadded
    Base64Url.fromByteVector(bytes)

  private def toByteVectorUnsigned(bigInt: BigInt): ByteVector = {
    val bitLen = ((bigInt.bitLength + 7) >> 3) << 3
    val bigBytes = ByteVector(bigInt.toByteArray)
    if bigInt.bitLength % 8 != 0 && (bigInt.bitLength / 8) + 1 == bitLen / 8 then
      bigBytes
    else
      val src = if bigInt.bitLength % 8 == 0 then bigBytes.tail else bigBytes
      val startDst = bitLen / 8 - src.length
      ByteVector.fill(startDst)(0) ++ src
  }

  private def octetKeyPairSubType(publicKey: PublicKey, privateKey: Option[PrivateKey])
  : Either[JsonWebKeyCreationError, (OctetKeyPairAlgorithm, Base64Url, Option[Base64Url])] =
    publicKey match
      case xecPublicKey: XECPublicKey =>
        xecPublicKey.getParams match
          case namedParameterSpec: NamedParameterSpec =>
            val xdhPrimeByteLengthEither: Either[JsonWebKeyCreationError, (JsonWebKey.XDH, BigInt, Int)] =
              namedParameterSpec.getName match
                case X25519.algorithm => (X25519, X25519.prime, 32).asRight
                case X448.algorithm => (X448, X448.prime, 57).asRight
                case name => UnsupportedKeyAlgorithm(name).asLeft
            for
              tuple <- xdhPrimeByteLengthEither
              eccPrivateKey <- rawOctetKeyPairPrivateKey[XECPrivateKey](privateKey)(_.getScalar)
              (xdh, prime, byteLength) = tuple
              xCoordinate = Base64Url.fromByteVector(adjustByteVectorLength(
                ByteVector(BigInt(xecPublicKey.getU).mod(prime).toByteArray).reverse,
                byteLength
              ))
            yield (xdh, xCoordinate, eccPrivateKey)
          case params => UncheckedParameterSpec(using scala.reflect.ClassTag(params.getClass)).asLeft
      case edECPublicKey: EdECPublicKey =>
        val edDSAByteLengthEither: Either[JsonWebKeyCreationError, (JsonWebKey.EdDSA, Int)] =
          edECPublicKey.getParams.getName match
            case Ed25519.algorithm => (Ed25519, 32).asRight
            case Ed448.algorithm => (Ed448, 57).asRight
            case name => UnsupportedKeyAlgorithm(name).asLeft
        for
          tuple <- edDSAByteLengthEither
          eccPrivateKey <- rawOctetKeyPairPrivateKey[EdECPrivateKey](privateKey)(_.getBytes)
          (edDSA, byteLength) = tuple
          edECPoint = edECPublicKey.getPoint
          yReversedBytes = adjustByteVectorLength(ByteVector(edECPoint.getY.toByteArray).reverse, byteLength)
          byteToOrWith = if edECPoint.isXOdd then -128.toByte else 0.toByte
          xCoordinate = Base64Url.fromByteVector(yReversedBytes.lastOption.fold(yReversedBytes)(
            last => yReversedBytes.init :+ (last | byteToOrWith).toByte
          ))
        yield (edDSA, xCoordinate, eccPrivateKey)
      case _ => UncheckedOctetKeyPairKeyType(using ClassTag(publicKey.getClass)).asLeft

  private def rawOctetKeyPairPrivateKey[A](privateKey: Option[PrivateKey])(bytes: A => Optional[Array[Byte]])
                                          (using classTag: ClassTag[A])
  : Either[JsonWebKeyCreationError, Option[Base64Url]] =
    privateKey match
      case Some(privateKey: A) =>
        Base64Url.fromByteVector(bytes(privateKey).toScala.fold(ByteVector.empty)(ByteVector.apply))
          .some.asRight[JsonWebKeyCreationError]
      case Some(privateKey) => MismatchedKeyPair[A].asLeft[Option[Base64Url]]
      case None => none[Base64Url].asRight[JsonWebKeyCreationError]

  private def adjustByteVectorLength(bytes: ByteVector, length: Int): ByteVector =
    if bytes.length > length then bytes.take(length)
    else if bytes.length == length then bytes
    else bytes ++ ByteVector.fill(length - bytes.length)(0)

  private val applicableKeyAlgorithms: Set[Algorithm] = Set(Ed448, Ed25519, EdDSA, X25519, X448, XDH)
end JsonWebKeyCompanion
