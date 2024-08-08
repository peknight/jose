package com.peknight.jose.jwk

import cats.data.NonEmptyList
import cats.syntax.either.*
import cats.syntax.option.*
import com.peknight.codec.base.{Base64, Base64Url}
import com.peknight.jose.error.jwk.*
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.JsonWebKey.*
import com.peknight.jose.key.OctetKeyPairOps
import com.peknight.security.algorithm.Algorithm
import com.peknight.security.key.agreement.XDH
import com.peknight.security.signature.EdDSA
import org.http4s.Uri
import scodec.bits.ByteVector

import java.math.BigInteger
import java.security.interfaces.*
import java.security.spec.EllipticCurve
import java.security.{Key, PrivateKey, PublicKey}
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
  ): Either[JsonWebKeyError, JsonWebKey] =
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
  ): Either[JsonWebKeyError, JsonWebKey] =
    publicKey match
      case rsaPublicKey: RSAPublicKey =>
        privateKey match
          case Some(rsaPrivateKey: RSAPrivateKey) =>
            fromRSAKey(rsaPublicKey, Some(rsaPrivateKey), otherPrimesInfo, publicKeyUse, keyOperations, algorithm,
              keyID, x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
            ).asRight[JsonWebKeyError]
          case Some(privKey) => MismatchedKeyPair(using ClassTag(privKey.getClass)).asLeft
          case None =>
            fromRSAKey(rsaPublicKey, None, otherPrimesInfo, publicKeyUse, keyOperations, algorithm,
              keyID, x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
            ).asRight[JsonWebKeyError]
      case ecPublicKey: ECPublicKey =>
        privateKey match
          case Some(ecPrivateKey: ECPrivateKey) =>
            fromEllipticCurveKey(ecPublicKey, Some(ecPrivateKey), curve, publicKeyUse, keyOperations, algorithm, keyID,
              x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
            )
          case Some(privKey) => MismatchedKeyPair(using ClassTag(privKey.getClass)).asLeft
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
        case d: RSAPrivateCrtKey => Option(f(d)).map(b => Base64Url.fromBigInt(BigInt(b)))
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
  ): Either[JsonWebKeyError, EllipticCurveJsonWebKey] =
    val ellipticCurve: EllipticCurve = ecPublicKey.getParams.getCurve
    for
      curve <- Curve.curveMap.get(ellipticCurve).orElse(curve).toRight[JsonWebKeyError](NoSuchCurve)
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
  ): Either[JsonWebKeyError, OctetKeyPairJsonWebKey] =
    for
      keyPairOps <- OctetKeyPairOps.getKeyPairOps(publicKey)
      curve <- keyPairOps.getAlgorithm(publicKey)
      publicKeyBytes <- keyPairOps.rawPublicKey(publicKey)
      xCoordinate = Base64Url.fromByteVector(publicKeyBytes)
      privateKeyBytes <- privateKey.fold(none[ByteVector].asRight[JsonWebKeyError])(
        privateK => keyPairOps.rawPrivateKey(privateK).map(_.some)
      )
      eccPrivateKey = privateKeyBytes.map(Base64Url.fromByteVector)
    yield
      OctetKeyPairJsonWebKey(
        curve,
        xCoordinate,
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

  private val applicableKeyAlgorithms: Set[Algorithm] = Set(Ed448, Ed25519, EdDSA, X25519, X448, XDH)
end JsonWebKeyCompanion
