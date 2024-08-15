package com.peknight.jose.jwk.ops

import cats.effect.Sync
import cats.syntax.either.*
import com.peknight.jose.error.jwk.{JsonWebKeyError, UnsupportedKeyAlgorithm}
import com.peknight.jose.jwk.JsonWebKey.OctetKeyPairAlgorithm
import com.peknight.security.key.factory.KeyFactoryAlgorithm
import com.peknight.security.key.pair.KeyPairGeneratorAlgorithm
import com.peknight.security.provider.Provider
import com.peknight.security.signature.{Ed25519, Ed448, EdDSA}
import com.peknight.security.spec.{NamedParameterSpec, NamedParameterSpecName}
import scodec.bits.ByteVector

import java.security.interfaces.{EdECPrivateKey, EdECPublicKey}
import java.security.spec.{EdECPoint, EdECPrivateKeySpec, EdECPublicKeySpec}
import java.security.{PrivateKey, PublicKey, Provider as JProvider}
import scala.jdk.OptionConverters.*

object EdDSAKeyOps extends OctetKeyPairOps[EdECPublicKey, EdECPrivateKey]:
  def keyAlgorithm: KeyFactoryAlgorithm & KeyPairGeneratorAlgorithm = com.peknight.security.signature.EdDSA

  def toPublicKey[F[_] : Sync](publicKeyBytes: ByteVector, algorithm: NamedParameterSpecName,
                               provider: Option[Provider | JProvider] = None): F[PublicKey] =
    val xIsOdd = publicKeyBytes.lastOption.map(_ & -128).exists(_ != 0)
    val ep = new EdECPoint(xIsOdd, BigIntOps.fromBytes(publicKeyBytes.lastOption
      .fold(publicKeyBytes)(last => publicKeyBytes.init :+ (last & 127).toByte)
      .reverse
    ).bigInteger)
    val keySpec = new EdECPublicKeySpec(NamedParameterSpec(algorithm), ep)
    generatePublic[F](keySpec, provider)

  def toPrivateKey[F[_]: Sync](privateKeyBytes: ByteVector, algorithm: NamedParameterSpecName,
                               provider: Option[Provider | JProvider] = None): F[PrivateKey] =
    generatePrivate[F](
      new EdECPrivateKeySpec(NamedParameterSpec(algorithm), privateKeyBytes.toArray),
      provider
    )

  def rawTypedPublicKey(edECPublicKey: EdECPublicKey): Either[JsonWebKeyError, ByteVector] =
    for
      byteLength <- getByteLength(edECPublicKey)
    yield
      val edECPoint = edECPublicKey.getPoint
      val yReversedBytes = adjustByteVectorLength(ByteVector(edECPoint.getY.toByteArray).reverse, byteLength)
      val byteToOrWith = if edECPoint.isXOdd then -128.toByte else 0.toByte
      yReversedBytes.lastOption.fold(yReversedBytes)(last => yReversedBytes.init :+ (last | byteToOrWith).toByte)

  def rawTypedPrivateKey(edEcPrivateKey: EdECPrivateKey): ByteVector =
    edEcPrivateKey.getBytes.toScala.fold(ByteVector.empty)(ByteVector.apply)

  def getTypedAlgorithm(edECPublicKey: EdECPublicKey): Either[JsonWebKeyError, OctetKeyPairAlgorithm] =
    handlePublicKey(edECPublicKey) {
      case Ed25519.algorithm => Ed25519
      case Ed448.algorithm => Ed448
    }

  private def getByteLength(edECPublicKey: EdECPublicKey): Either[JsonWebKeyError, Int] =
    handlePublicKey(edECPublicKey) {
      case Ed25519.algorithm => 32
      case Ed448.algorithm => 57
    }

  private def handlePublicKey[A](edECPublicKey: EdECPublicKey)(f: PartialFunction[String, A])
  : Either[JsonWebKeyError, A] =
    val name = edECPublicKey.getParams.getName
    if f.isDefinedAt(name) then f(name).asRight else UnsupportedKeyAlgorithm(name).asLeft
end EdDSAKeyOps
