package com.peknight.jose.jws.ops

import cats.effect.Sync
import com.peknight.jose.error.jws.{InvalidHmacSHAKeyLength, JsonWebSignatureError}
import com.peknight.jose.jwa.signature.HmacSHAAlgorithm
import com.peknight.security.crypto.Mac
import com.peknight.security.provider.Provider
import scodec.bits.ByteVector

import java.security.{Key, Provider as JProvider}

object HmacSHAOps:
  def sign[F[_]: Sync](algorithm: HmacSHAAlgorithm, key: Key, input: ByteVector,
                       provider: Option[Provider | JProvider] = None): F[ByteVector] =
    Mac.mac[F](algorithm.mac, key, input, provider)

  def validateKey(algorithm: HmacSHAAlgorithm, key: Key): Either[JsonWebSignatureError, Unit] =
    Option(key.getEncoded).map(_.length * 8) match
      case Some(bitLength) =>
        val minimumKeyLength = algorithm.mac.digest.bitLength
        if bitLength < minimumKeyLength then
          Left(InvalidHmacSHAKeyLength(algorithm, bitLength, minimumKeyLength))
        else Right(())
      case _ => Right(())
end HmacSHAOps
