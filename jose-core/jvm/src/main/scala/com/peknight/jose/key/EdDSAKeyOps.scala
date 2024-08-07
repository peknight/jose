package com.peknight.jose.key

import cats.syntax.either.*
import com.peknight.jose.error.jwk.{JsonWebKeyError, UnsupportedKeyAlgorithm}
import com.peknight.jose.jwk.JsonWebKey.{Ed25519, Ed448, EdDSA}
import scodec.bits.ByteVector

import java.security.interfaces.{EdECPrivateKey, EdECPublicKey}
import scala.jdk.OptionConverters.*

object EdDSAKeyOps extends OctetKeyPairOps[EdECPublicKey, EdECPrivateKey, EdDSA]:
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

  def getTypedAlgorithm(edECPublicKey: EdECPublicKey): Either[JsonWebKeyError, EdDSA] =
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
