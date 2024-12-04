package com.peknight.jose.jwt

import cats.data.EitherT
import cats.effect.Async
import cats.syntax.either.*
import cats.{Id, Monad}
import com.peknight.cats.ext.syntax.eitherT.{eLiftET, lLiftET, rLiftET}
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.encryption.KeyDecipherMode
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jws.JsonWebSignature
import com.peknight.jose.jwx.{JoseConfiguration, JsonWebStructure}
import com.peknight.security.provider.Provider
import fs2.compression.Compression

import java.security.{Key, SecureRandom, Provider as JProvider}

trait JsonWebTokenCompanion:
  //def parse[F[_]: Async: Compression](jwt: String, configuration: JoseConfiguration = JoseConfiguration.default)
  //                                   (verificationKey: (JsonWebSignature, JoseConfiguration) => F[Either[Error, Option[Key]]])
  //                                   (decryptionKey: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, Key]])
  //: F[Either[Error, JsonWebTokenClaims]] =
  //  case class State(
  //                    hasSignature: Boolean = false,
  //                    hasEncryption: Boolean = false,
  //                    hasSymmetricEncryption: Boolean = false
  //                  )
  //  def nextState(structure: JsonWebStructure, state: State): Either[Error, State] =
  //    structure.getUnprotectedHeader.map { header =>

  //      state
  //    }

  //  Monad[[X] =>> EitherT[F, Error, X]].tailRecM[(String, State), (JsonWebTokenClaims, State)]((jwt, State())) {
  //    case (jwt, State(hasSignature, hasEncryption, hasSymmetricEncryption)) =>
  //      for
  //        structure <- JsonWebStructure.parse(jwt).eLiftET[F]
  //        payload <- EitherT(structure.getPayloadString[F](skipSignatureVerification, skipVerificationKeyResolutionOnNone,
  //          knownCriticalHeaders, doKeyValidation, useLegacyName, keyDecipherModeOverride, random, cipherProvider,
  //          keyAgreementProvider, keyFactoryProvider, macProvider, messageDigestProvider, signatureProvider
  //        )(verificationKey)(decryptionKey))
  //        nestedJwt <- structure.isNestedJsonWebToken.eLiftET[F]
  //        res <-
  //          if nestedJwt then payload.asLeft.rLiftET
  //          else
  //            decode[Id, JsonWebTokenClaims](payload) match
  //              case Left(error) => if liberalContentTypeHandling then payload.asLeft.rLiftET else error.lLiftET
  //              case Right(jwtClaims) => jwtClaims.asRight.rLiftET
  //      yield
  //        res
  //    }
  //    .value

end JsonWebTokenCompanion
