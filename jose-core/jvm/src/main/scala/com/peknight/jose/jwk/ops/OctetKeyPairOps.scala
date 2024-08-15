package com.peknight.jose.jwk.ops

import cats.effect.Sync
import cats.syntax.either.*
import com.peknight.jose.error.jwk.{JsonWebKeyError, UnsupportedKey, UnsupportedKeyAlgorithm}
import com.peknight.jose.error.{UncheckedPrivateKey, UncheckedPublicKey}
import com.peknight.jose.jwk.JsonWebKey.OctetKeyPairAlgorithm
import com.peknight.security.algorithm.Algorithm
import com.peknight.security.key.agreement.XDH
import com.peknight.security.provider.Provider
import com.peknight.security.signature.EdDSA
import com.peknight.security.spec.{NamedParameterSpec, NamedParameterSpecName}
import scodec.bits.ByteVector

import java.security.interfaces.{EdECPublicKey, XECPublicKey}
import java.security.{KeyPair, PrivateKey, PublicKey, SecureRandom, Provider as JProvider}
import scala.reflect.ClassTag

trait OctetKeyPairOps[PublicK <: PublicKey : ClassTag, PrivateK <: PrivateKey : ClassTag]
  extends KeyPairOps:

  def toPublicKey[F[_]: Sync](publicKeyBytes: ByteVector, algorithm: NamedParameterSpecName, provider: Option[Provider | JProvider] = None)
  : F[PublicKey]

  def toPrivateKey[F[_]: Sync](privateKeyBytes: ByteVector, algorithm: NamedParameterSpecName, provider: Option[Provider | JProvider] = None)
  : F[PrivateKey]

  def generateKeyPair[F[_]: Sync](name: NamedParameterSpecName, provider: Option[Provider | JProvider] = None,
                                  random: Option[SecureRandom] = None): F[KeyPair] =
    paramsGenerateKeyPair[F](NamedParameterSpec(name), provider, random)

  def rawTypedPublicKey(publicKey: PublicK): Either[JsonWebKeyError, ByteVector]

  def rawTypedPrivateKey(privateKey: PrivateK): ByteVector

  def getTypedAlgorithm(publicKey: PublicK): Either[JsonWebKeyError, OctetKeyPairAlgorithm]

  def rawPublicKey(publicKey: PublicKey): Either[JsonWebKeyError, ByteVector] =
    checkPublicKeyType(publicKey).flatMap(rawTypedPublicKey)

  def rawPrivateKey(privateKey: PrivateKey): Either[JsonWebKeyError, ByteVector] =
    checkPrivateKeyType(privateKey).map(rawTypedPrivateKey)

  def getAlgorithm(publicKey: PublicKey): Either[JsonWebKeyError, OctetKeyPairAlgorithm] =
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
  def getKeyPairOps(publicKey: PublicKey): Either[JsonWebKeyError, OctetKeyPairOps[?, ?]] =
    publicKey match
      case _: XECPublicKey => XDHKeyOps.asRight
      case _: EdECPublicKey => EdDSAKeyOps.asRight
      case _ => UnsupportedKey(publicKey.getAlgorithm)(using ClassTag(publicKey.getClass)).asLeft

  def getKeyPairOps(curve: Algorithm): Either[JsonWebKeyError, OctetKeyPairOps[?, ?]] =
    curve match
      case _: XDH => XDHKeyOps.asRight
      case _: EdDSA => EdDSAKeyOps.asRight
      case _ => UnsupportedKeyAlgorithm(curve.algorithm).asLeft
end OctetKeyPairOps
