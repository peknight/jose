package com.peknight.jose.key

import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.jose.error.jwk.{JsonWebKeyError, UncheckedParameterSpec, UnsupportedKeyAlgorithm}
import com.peknight.jose.jwk.JsonWebKey.{X25519, X448, XDH}
import com.peknight.security.KeyFactory
import com.peknight.security.key.factory.KeyFactoryAlgorithm
import com.peknight.security.provider.Provider
import com.peknight.security.spec.NamedParameterSpec
import com.peknight.security.syntax.keyFactory.generatePublicF
import scodec.bits.ByteVector

import java.security.KeyFactory as JKeyFactory
import java.security.interfaces.{XECPrivateKey, XECPublicKey}
import java.security.spec.{XECPublicKeySpec, NamedParameterSpec as JNamedParameterSpec}
import scala.jdk.OptionConverters.*
import scala.reflect.ClassTag

object XDHKeyOps extends OctetKeyPairOps[XECPublicKey, XECPrivateKey, XDH]:

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

  private def toPublicKey[F[_]: Sync](publicKeyBytes: ByteVector, algorithm: XDH, provider: Option[Provider]): F[XECPublicKey] =
    val reversedBytes = publicKeyBytes.reverse
    val numBits =
      algorithm match
        case X25519 => 255
        case X448 => 448
    val numBitsMod8 = numBits % 8
    val keySpec = new XECPublicKeySpec(
      NamedParameterSpec(algorithm),
      BigInt(1, reversedBytes.headOption.filter(_ => numBitsMod8 != 0).fold(reversedBytes)(
        head => (head & ((1 << numBitsMod8) - 1)).toByte +: reversedBytes.tail
      ).toArray).bigInteger
    )
    for
      factory <- keyFactory[F](provider)
      publicKey <- factory.generatePublicF(keySpec)
    yield
      publicKey.asInstanceOf[XECPublicKey]

  private def keyFactoryAlgorithm: KeyFactoryAlgorithm = com.peknight.security.key.agreement.XDH

  private def keyFactory[F[_]: Sync](provider: Option[Provider]): F[JKeyFactory] =
    KeyFactory.getInstance[F](keyFactoryAlgorithm, provider)
end XDHKeyOps
