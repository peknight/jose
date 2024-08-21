package com.peknight.jose.jwk

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.syntax.option.*
import com.peknight.codec.error.DecodingFailure
import com.peknight.commons.bigint.syntax.byteVector.toUnsignedBigInt
import com.peknight.jose.jwk.JsonWebKey.RSAJsonWebKey
import com.peknight.jose.jwk.ops.RSAKeyOps
import com.peknight.security.provider.Provider

import java.security.{PrivateKey, PublicKey, Provider as JProvider}

trait RSAJsonWebKeyPlatform extends AsymmetricJsonWebKeyPlatform { self: RSAJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, PublicKey]] =
    val eitherT =
      for
        modulus <- EitherT(self.modulus.decode[F])
        publicExponent <- EitherT(self.exponent.decode[F])
        rsaPublicKey <- EitherT(RSAKeyOps.toPublicKey[F](modulus.toUnsignedBigInt, publicExponent.toUnsignedBigInt,
          provider).map(_.asRight))
      yield
        rsaPublicKey
    eitherT.value

  def toPrivateKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, Option[PrivateKey]]] =
    self.privateExponent.fold(none[PrivateKey].asRight[DecodingFailure].pure[F]) { privateExponent =>
      val eitherT =
        for
          modulus <- EitherT(self.modulus.decode[F])
          privateExponent <- EitherT(privateExponent.decode[F])
          rsaPrivateKey <-
            val crtEitherTOption =
              for
                firstPrimeFactor <- self.firstPrimeFactor
                secondPrimeFactor <- self.secondPrimeFactor
                firstFactorCRTExponent <- self.firstFactorCRTExponent
                secondFactorCRTExponent <- self.secondFactorCRTExponent
                firstCRTCoefficient <- self.firstCRTCoefficient
              yield
                for
                  publicExponent <- EitherT(self.exponent.decode[F])
                  primeP <- EitherT(firstPrimeFactor.decode[F])
                  primeQ <- EitherT(secondPrimeFactor.decode[F])
                  primeExponentP <- EitherT(firstFactorCRTExponent.decode[F])
                  primeExponentQ <- EitherT(secondFactorCRTExponent.decode[F])
                  crtCoefficient <- EitherT(firstCRTCoefficient.decode[F])
                  privateKey <- EitherT(RSAKeyOps.toPrivateKey[F](
                    modulus.toUnsignedBigInt,
                    publicExponent.toUnsignedBigInt,
                    privateExponent.toUnsignedBigInt,
                    primeP.toUnsignedBigInt,
                    primeQ.toUnsignedBigInt,
                    primeExponentP.toUnsignedBigInt,
                    primeExponentQ.toUnsignedBigInt,
                    crtCoefficient.toUnsignedBigInt,
                    provider
                  ).map(_.asRight))
                yield
                  privateKey
            crtEitherTOption.getOrElse(EitherT(RSAKeyOps.toPrivateKey[F](
              modulus.toUnsignedBigInt, privateExponent.toUnsignedBigInt, provider
            ).map(_.asRight)))
        yield
          rsaPrivateKey
      eitherT.value.map(_.map(_.some))
    }
}
