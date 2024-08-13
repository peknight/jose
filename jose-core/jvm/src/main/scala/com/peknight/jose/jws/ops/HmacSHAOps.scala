package com.peknight.jose.jws.ops

import cats.effect.Sync
import cats.syntax.functor.*
import com.peknight.jose.error.jws.{InvalidHmacSHAKeyLength, JsonWebSignatureError}
import com.peknight.jose.jwa.signature.HmacSHAAlgorithm
import com.peknight.security.mac.MAC
import com.peknight.security.provider.Provider
import scodec.bits.ByteVector

import java.security.{Key, Provider as JProvider}

object HmacSHAOps:
  def sign[F[_]: Sync](algorithm: HmacSHAAlgorithm, key: Key, input: ByteVector,
                       provider: Option[Provider | JProvider] = None): F[ByteVector] =
    MAC.mac[F](algorithm.mac, key, input, provider)

  def verify[F[_]: Sync](algorithm: HmacSHAAlgorithm, key: Key, input: ByteVector, signature: ByteVector,
                         provider: Option[Provider | JProvider] = None): F[Boolean] =
    given CanEqual[ByteVector, ByteVector] = CanEqual.derived
    sign[F](algorithm, key, input, provider).map(_ == signature)

  def validateKey(algorithm: HmacSHAAlgorithm, key: Key): Either[JsonWebSignatureError, Unit] =
    Option(key.getEncoded).map(_.length * 8) match
      case Some(bitLength) =>
        val minimumKeyLength = algorithm.mac.digest.bitLength
        if bitLength < minimumKeyLength then
          Left(InvalidHmacSHAKeyLength(algorithm, bitLength, minimumKeyLength))
        else Right(())
      case _ => Right(())
end HmacSHAOps
