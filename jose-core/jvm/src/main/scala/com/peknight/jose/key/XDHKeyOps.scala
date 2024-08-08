package com.peknight.jose.key

import cats.effect.Sync
import cats.syntax.either.*
import com.peknight.jose.error.jwk.{JsonWebKeyError, UncheckedParameterSpec, UnsupportedKeyAlgorithm}
import com.peknight.jose.jwk.JsonWebKey.{X25519, X448, XDH}
import com.peknight.security.key.factory.KeyFactoryAlgorithm
import com.peknight.security.provider.Provider
import com.peknight.security.spec.NamedParameterSpec
import scodec.bits.ByteVector

import java.security.interfaces.{XECPrivateKey, XECPublicKey}
import java.security.spec.{XECPrivateKeySpec, XECPublicKeySpec, NamedParameterSpec as JNamedParameterSpec}
import scala.jdk.OptionConverters.*
import scala.reflect.ClassTag

object XDHKeyOps extends OctetKeyPairOps[XECPublicKey, XECPrivateKey, XDH]:
  def keyFactoryAlgorithm: KeyFactoryAlgorithm = com.peknight.security.key.agreement.XDH

  def toPublicKey[F[_]: Sync](publicKeyBytes: ByteVector, algorithm: XDH, provider: Option[Provider]): F[XECPublicKey] =
    val reversedBytes = publicKeyBytes.reverse
    val numBits =
      algorithm match
        case X25519 => 255
        case X448 => 448
    val numBitsMod8 = numBits % 8
    val keySpec = new XECPublicKeySpec(
      NamedParameterSpec(algorithm),
      BigIntOps.fromBytes(reversedBytes.headOption.filter(_ => numBitsMod8 != 0).fold(reversedBytes)(
        head => (head & ((1 << numBitsMod8) - 1)).toByte +: reversedBytes.tail
      )).bigInteger
    )
    generatePublicKey[F, XECPublicKey](keySpec, provider)

  def toPrivateKey[F[_]: Sync](privateKeyBytes: ByteVector, algorithm: XDH, provider: Option[Provider]): F[XECPrivateKey] =
    generatePrivateKey[F, XECPrivateKey](
      new XECPrivateKeySpec(NamedParameterSpec(algorithm), privateKeyBytes.toArray),
      provider
    )

  def rawTypedPublicKey(xecPublicKey: XECPublicKey): Either[JsonWebKeyError, ByteVector] =
    for
      prime <- getPrime(xecPublicKey)
      byteLength <- getByteLength(xecPublicKey)
    yield
      adjustByteVectorLength(ByteVector(BigInt(xecPublicKey.getU).mod(prime).toByteArray).reverse, byteLength)

  def rawTypedPrivateKey(xecPrivateKey: XECPrivateKey): ByteVector =
    xecPrivateKey.getScalar.toScala.fold(ByteVector.empty)(ByteVector.apply)

  def getTypedAlgorithm(xecPublicKey: XECPublicKey): Either[JsonWebKeyError, XDH] =
    handlePublicKey(xecPublicKey) {
      case X25519.algorithm => X25519
      case X448.algorithm => X448
    }

  private def getPrime(xecPublicKey: XECPublicKey): Either[JsonWebKeyError, BigInt] =
    handlePublicKey(xecPublicKey) {
      case X25519.algorithm => X25519.prime
      case X448.algorithm => X448.prime
    }

  private def getByteLength(xecPublicKey: XECPublicKey): Either[JsonWebKeyError, Int] =
    handlePublicKey(xecPublicKey) {
      case X25519.algorithm => 32
      case X448.algorithm => 57
    }

  private def handlePublicKey[A](xecPublicKey: XECPublicKey)(f: PartialFunction[String, A])
  : Either[JsonWebKeyError, A] =
    xecPublicKey.getParams match
      case namedParameterSpec: JNamedParameterSpec =>
        val name = namedParameterSpec.getName
        if f.isDefinedAt(name) then f(name).asRight else UnsupportedKeyAlgorithm(name).asLeft
      case params => UncheckedParameterSpec(using scala.reflect.ClassTag(params.getClass)).asLeft

end XDHKeyOps
