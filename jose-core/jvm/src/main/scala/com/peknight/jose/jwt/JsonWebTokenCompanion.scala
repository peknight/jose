package com.peknight.jose.jwt

import cats.data.{EitherT, NonEmptyList}
import cats.effect.Async
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.{Id, Monad}
import com.peknight.cats.ext.syntax.eitherT.{eLiftET, lLiftET, rLiftET}
import com.peknight.codec.circe.parser.decode
import com.peknight.error.Error
import com.peknight.jose.error.{InvalidJsonWebToken, MissingEncryption, MissingIntegrity, MissingSignature}
import com.peknight.jose.jwe.{DecryptionPrimitive, JsonWebEncryption}
import com.peknight.jose.jws.{JsonWebSignature, VerificationPrimitive}
import com.peknight.jose.jwx.{JoseConfiguration, JoseHeader, JsonWebStructure}
import fs2.compression.Compression

trait JsonWebTokenCompanion:
  def getClaims[F[_]: Async: Compression](jwt: String, configuration: JoseConfiguration = JoseConfiguration.default)
                                         (verificationPrimitiveF: (JsonWebSignature, JoseConfiguration) => F[Either[Error, VerificationPrimitive]])
                                         (decryptionPrimitiveF: (JsonWebEncryption, JoseConfiguration) => F[Either[Error, DecryptionPrimitive]])
  : F[Either[Error, JsonWebTokenClaims]] =
    case class State(
                      hasSignature: Boolean = false,
                      hasEncryption: Boolean = false,
                      hasSymmetricEncryption: Boolean = false
                    ):
      def next(structure: JsonWebStructure, header: JoseHeader): State =
        val hasSignature = structure.isInstanceOf[JsonWebSignature] && !header.isNoneAlgorithm
        val hasEncryption = structure.isInstanceOf[JsonWebEncryption]
        val hasSymmetricEncryption = hasEncryption && header.isSymmetric
        copy(
          hasSignature = this.hasSignature || hasSignature,
          hasEncryption = this.hasEncryption || hasEncryption,
          hasSymmetricEncryption = this.hasSymmetricEncryption || hasSymmetricEncryption
        )
    end State
    extension [A] (eitherT: EitherT[F, Error, A])
      private def invalid(jwt: String, nested: List[JsonWebStructure]): EitherT[F, Error, A] =
        EitherT(eitherT.value.map(_.left.map(e => InvalidJsonWebToken(jwt, nested, Some(e)))))
    end extension
    Monad[[X] =>> EitherT[F, Error, X]]
      .tailRecM[
        (String, List[JsonWebStructure], State),
        (JsonWebTokenClaims, String, NonEmptyList[JsonWebStructure], State)
      ]((jwt, Nil, State())) {
        case (jwt, nested, state) =>
          for
            structure <- JsonWebStructure.parse(jwt).eLiftET[F].invalid(jwt, nested)
            payload <- EitherT(structure.getPayloadString[F](configuration)(verificationPrimitiveF)(decryptionPrimitiveF))
              .invalid(jwt, nested)
            header <- structure.getUnprotectedHeader.eLiftET[F].invalid(jwt, nested)
            nextNested = structure :: nested
            nextState = state.next(structure, header)
            res <-
              if header.isNestedJsonWebToken then (payload, nextNested, nextState).asLeft.rLiftET
              else
                decode[Id, JsonWebTokenClaims](payload) match
                  case Left(error) =>
                    if configuration.liberalContentTypeHandling then (payload, nextNested, nextState).asLeft.rLiftET
                    else error.lLiftET.invalid(jwt, nested)
                  case Right(jwtClaims) => (jwtClaims, jwt, NonEmptyList(structure, nested), nextState).asRight.rLiftET
          yield
            res
      }
      .value
      .map(_.flatMap { case (claims, jwt, nested, State(hasSignature, hasEncryption, hasSymmetricEncryption)) =>
        if configuration.requireSignature && !hasSignature then
          InvalidJsonWebToken(jwt, nested.toList, Some(MissingSignature)).asLeft
        else if configuration.requireEncryption && !hasEncryption then
          InvalidJsonWebToken(jwt, nested.toList, Some(MissingEncryption)).asLeft
        else if configuration.requireIntegrity && !hasSignature && !hasSymmetricEncryption then
          InvalidJsonWebToken(jwt, nested.toList, Some(MissingIntegrity)).asLeft
        else
          claims.asRight
      })
end JsonWebTokenCompanion
