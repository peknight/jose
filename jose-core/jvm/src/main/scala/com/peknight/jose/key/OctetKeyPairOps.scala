package com.peknight.jose.key

import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.jose.error.jwk.{JsonWebKeyError, UncheckedPrivateKey, UncheckedPublicKey, UnsupportedKey}
import com.peknight.jose.jwk.JsonWebKey.{EdDSA, OctetKeyPairAlgorithm, XDH}
import com.peknight.security.provider.Provider
import com.peknight.security.spec.{NamedParameterSpec, NamedParameterSpecName}
import com.peknight.security.syntax.keyPairGenerator.{generateKeyPairF, initializeF}
import scodec.bits.ByteVector

import java.security.interfaces.{EdECPublicKey, XECPublicKey}
import java.security.{KeyPair, PrivateKey, PublicKey, SecureRandom}
import scala.reflect.ClassTag

trait OctetKeyPairOps[PublicK <: PublicKey : ClassTag, PrivateK <: PrivateKey : ClassTag, Algorithm <: OctetKeyPairAlgorithm]
  extends KeyPairOps:

  def toPublicKey[F[_]: Sync](publicKeyBytes: ByteVector, algorithm: Algorithm, provider: Option[Provider] = None)
  : F[PublicKey]

  def toPrivateKey[F[_]: Sync](privateKeyBytes: ByteVector, algorithm: Algorithm, provider: Option[Provider] = None)
  : F[PrivateKey]

  def generateKeyPair[F[_]: Sync](name: NamedParameterSpecName, provider: Option[Provider] = None, secureRandom: Option[SecureRandom]): F[KeyPair] =
    for
      generator <- keyPairGenerator[F](provider)
      _ <- generator.initializeF[F](NamedParameterSpec(name), secureRandom)
      keyPair <- generator.generateKeyPairF[F]
    yield
      keyPair

  def rawTypedPublicKey(publicKey: PublicK): Either[JsonWebKeyError, ByteVector]

  def rawTypedPrivateKey(privateKey: PrivateK): ByteVector

  def getTypedAlgorithm(publicKey: PublicK): Either[JsonWebKeyError, Algorithm]

  def rawPublicKey(publicKey: PublicKey): Either[JsonWebKeyError, ByteVector] =
    checkPublicKeyType(publicKey).flatMap(rawTypedPublicKey)

  def rawPrivateKey(privateKey: PrivateKey): Either[JsonWebKeyError, ByteVector] =
    checkPrivateKeyType(privateKey).map(rawTypedPrivateKey)

  def getAlgorithm(publicKey: PublicKey): Either[JsonWebKeyError, Algorithm] =
    checkPublicKeyType(publicKey).flatMap(getTypedAlgorithm)

  def checkPublicKeyType(publicKey: PublicKey): Either[JsonWebKeyError, PublicK] =
    publicKey match
      case publicK: PublicK => publicK.asRight
      case _ => UncheckedPublicKey(publicKey.getAlgorithm)(using ClassTag(publicKey.getClass)).asLeft

  def checkPrivateKeyType(privateKey: PrivateKey): Either[JsonWebKeyError, PrivateK] =
    privateKey match
      case privateK: PrivateK => privateK.asRight
      case _ => UncheckedPrivateKey(privateKey.getAlgorithm)(using ClassTag(privateKey.getClass)).asLeft

  def adjustByteVectorLength(bytes: ByteVector, length: Int): ByteVector =
    if bytes.length > length then bytes.take(length)
    else if bytes.length == length then bytes
    else bytes ++ ByteVector.fill(length - bytes.length)(0)
end OctetKeyPairOps
object OctetKeyPairOps:
  def getKeyPairOps(publicKey: PublicKey): Either[JsonWebKeyError, OctetKeyPairOps[?, ?, ?]] =
    publicKey match
      case _: XECPublicKey => XDHKeyOps.asRight
      case _: EdECPublicKey => EdDSAKeyOps.asRight
      case _ => UnsupportedKey(publicKey.getAlgorithm)(using ClassTag(publicKey.getClass)).asLeft

  def getKeyPairOps(curve: OctetKeyPairAlgorithm): OctetKeyPairOps[?, ?, ?] =
    curve match
      case _: XDH => XDHKeyOps
      case _: EdDSA => EdDSAKeyOps
end OctetKeyPairOps
