package com.peknight.jose.jwk

import cats.Id
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.syntax.option.*
import cats.syntax.traverse.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwk.JsonWebKey.RSAJsonWebKey
import com.peknight.security.cipher.RSA
import com.peknight.security.provider.Provider

import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.{PrivateKey, PublicKey, Provider as JProvider}

trait RSAJsonWebKeyPlatform extends AsymmetricJsonWebKeyPlatform { self: RSAJsonWebKey =>
  def toPublicKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, PublicKey]] =
    val either =
      for
        modulus <- self.modulus.decodeToUnsignedBigInt[Id]
        publicExponent <- self.exponent.decodeToUnsignedBigInt[Id]
      yield
        RSA.publicKey[F](modulus, publicExponent, provider).map(_.asInstanceOf[PublicKey]).asError
    either.fold(_.asLeft.pure, identity)

  def toPrivateKey[F[_]: Sync](provider: Option[Provider | JProvider] = None): F[Either[Error, Option[PrivateKey]]] =
    self.privateExponent.fold(none[RSAPrivateKey].asRight[Error].pure[F]) { privateExponent =>
      val either =
        for
          modulus <- self.modulus.decodeToUnsignedBigInt[Id]
          privateExponent <- privateExponent.decodeToUnsignedBigInt[Id]
          option =
            for
              firstPrimeFactor <- self.firstPrimeFactor
              secondPrimeFactor <- self.secondPrimeFactor
              firstFactorCRTExponent <- self.firstFactorCRTExponent
              secondFactorCRTExponent <- self.secondFactorCRTExponent
              firstCRTCoefficient <- self.firstCRTCoefficient
            yield
              for
                publicExponent <- self.exponent.decodeToUnsignedBigInt[Id]
                primeP <- firstPrimeFactor.decodeToUnsignedBigInt[Id]
                primeQ <- secondPrimeFactor.decodeToUnsignedBigInt[Id]
                primeExponentP <- firstFactorCRTExponent.decodeToUnsignedBigInt[Id]
                primeExponentQ <- secondFactorCRTExponent.decodeToUnsignedBigInt[Id]
                crtCoefficient <- firstCRTCoefficient.decodeToUnsignedBigInt[Id]
              yield
                (publicExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient)
          option <- option.sequence
        yield
          option match
            case Some((publicExponent, primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient)) =>
              RSA.privateCrtKey[F](modulus, publicExponent, privateExponent, primeP, primeQ, primeExponentP,
                primeExponentQ, crtCoefficient, provider).map(_.asInstanceOf[PrivateKey])
            case _ => RSA.privateKey[F](modulus, privateExponent, provider).map(_.asInstanceOf[PrivateKey])
      either.fold(_.asLeft.pure, f => f.map(Some.apply).asError)
    }
}
