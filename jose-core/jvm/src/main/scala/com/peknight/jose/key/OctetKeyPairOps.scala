package com.peknight.jose.key

import cats.syntax.either.*
import com.peknight.jose.error.jwk.{JsonWebKeyError, UncheckedPrivateKey, UncheckedPublicKey, UnsupportedKey}
import com.peknight.jose.jwk.JsonWebKey.OctetKeyPairAlgorithm
import scodec.bits.ByteVector

import java.security.interfaces.{EdECPublicKey, XECPublicKey}
import java.security.{PrivateKey, PublicKey}
import scala.reflect.ClassTag

trait OctetKeyPairOps[PublicK: ClassTag, PrivateK: ClassTag, Algorithm <: OctetKeyPairAlgorithm]:

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
end OctetKeyPairOps
