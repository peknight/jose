package com.peknight.jose.jwk

import cats.data.EitherT
import cats.syntax.either.*
import cats.syntax.option.*
import cats.syntax.functor.*
import cats.syntax.applicative.*
import cats.effect.Sync
import com.peknight.codec.error.DecodingFailure
import com.peknight.jose.jwk.JsonWebKey.RSAJsonWebKey
import com.peknight.jose.jwk.ops.{BigIntOps, RSAKeyOps}
import com.peknight.security.provider.Provider
import java.security.{PrivateKey, PublicKey, Provider as JProvider}

trait RSAJsonWebKeyPlatform extends AsymmetricJsonWebKeyPlatform { self: RSAJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[DecodingFailure, PublicKey]] =
    val eitherT =
      for
        modulus <- EitherT(self.modulus.decode[F])
        publicExponent <- EitherT(self.exponent.decode[F])
        rsaPublicKey <- EitherT(RSAKeyOps.toPublicKey[F](
          BigIntOps.fromBytes(modulus), BigIntOps.fromBytes(publicExponent), provider
        ).map(_.asRight))
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
                    BigIntOps.fromBytes(modulus),
                    BigIntOps.fromBytes(publicExponent),
                    BigIntOps.fromBytes(privateExponent),
                    BigIntOps.fromBytes(primeP),
                    BigIntOps.fromBytes(primeQ),
                    BigIntOps.fromBytes(primeExponentP),
                    BigIntOps.fromBytes(primeExponentQ),
                    BigIntOps.fromBytes(crtCoefficient),
                    provider
                  ).map(_.asRight))
                yield
                  privateKey
            crtEitherTOption.getOrElse(EitherT(RSAKeyOps.toPrivateKey[F](
              BigIntOps.fromBytes(modulus), BigIntOps.fromBytes(privateExponent), provider
            ).map(_.asRight)))
        yield
          rsaPrivateKey
      eitherT.value.map(_.map(_.some))
    }
}
