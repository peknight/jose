package com.peknight.jose.jws.ops

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import com.peknight.jose.error.UncheckedKey
import com.peknight.jose.error.jws.{JsonWebSignatureError, UncheckedAlgorithm, UnsupportedSignatureAlgorithm}
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.signature.*
import com.peknight.security.provider.Provider
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}
import scala.reflect.ClassTag

trait SignatureOps[Algorithm <: JsonWebAlgorithm : ClassTag, SigningKey <: Key : ClassTag, VerificationKey <: Key : ClassTag]:
  def sign[F[_]: Sync](algorithm: JsonWebAlgorithm, key: Key, data: ByteVector, doKeyValidation: Boolean = true,
                       useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None,
                       random: Option[SecureRandom] = None): F[Either[JsonWebSignatureError, ByteVector]] =
    algorithm match
      case algo: Algorithm => key match
        case k: SigningKey =>
          (if doKeyValidation then typedValidateSigningKey(algo, k) else ().asRight) match
            case Left(error) => error.asLeft.pure
            case Right(_) => typedSign[F](algo, k, data, useLegacyName, provider, random)
        case _ => UncheckedKey(key.getAlgorithm)(using ClassTag(key.getClass)).asLeft.pure
      case _ => UncheckedAlgorithm(algorithm).asLeft.pure

  def verify[F[_]: Sync](algorithm: JsonWebAlgorithm, key: Key, data: ByteVector, signed: ByteVector,
                         doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                         provider: Option[Provider | JProvider] = None): F[Either[JsonWebSignatureError, Boolean]] =
    algorithm match
      case algo: Algorithm => key match
        case k: VerificationKey =>
          (if doKeyValidation then typedValidateVerificationKey(algo, k) else ().asRight) match
            case Left(error) => error.asLeft.pure
            case Right(_) => typedVerify[F](algo, k, data, signed, useLegacyName, provider)
        case _ => UncheckedKey(key.getAlgorithm)(using ClassTag(key.getClass)).asLeft.pure
      case _ => UncheckedAlgorithm(algorithm).asLeft.pure


  def validateSigningKey(algorithm: JsonWebAlgorithm, key: Key): Either[JsonWebSignatureError, Unit] =
    algorithm match
      case algo: Algorithm => key match
        case k: SigningKey => typedValidateSigningKey(algo, k)
        case _ => UncheckedKey(key.getAlgorithm)(using ClassTag(key.getClass)).asLeft
      case _ => UncheckedAlgorithm(algorithm).asLeft

  def validateVerificationKey(algorithm: JsonWebAlgorithm, key: Key): Either[JsonWebSignatureError, Unit] =
    algorithm match
      case algo: Algorithm => key match
        case k: VerificationKey => typedValidateVerificationKey(algo, k)
        case _ => UncheckedKey(key.getAlgorithm)(using ClassTag(key.getClass)).asLeft
      case _ => UncheckedAlgorithm(algorithm).asLeft

  def typedSign[F[_]: Sync](algorithm: Algorithm, key: SigningKey, data: ByteVector,
                            useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None,
                            random: Option[SecureRandom] = None): F[Either[JsonWebSignatureError, ByteVector]]

  def typedVerify[F[_]: Sync](algorithm: Algorithm, key: VerificationKey, data: ByteVector, signed: ByteVector,
                              useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None)
  : F[Either[JsonWebSignatureError, Boolean]]

  def typedValidateSigningKey(algorithm: Algorithm, key: SigningKey): Either[JsonWebSignatureError, Unit]

  def typedValidateVerificationKey(algorithm: Algorithm, key: VerificationKey): Either[JsonWebSignatureError, Unit]
end SignatureOps
object SignatureOps:
  def getSignatureOps(algorithm: JsonWebAlgorithm): Either[JsonWebSignatureError, SignatureOps[?, ?, ?]] =
    algorithm match
      case algorithm: ECDSAAlgorithm => ECDSAOps.asRight
      case algorithm: HmacSHAAlgorithm => HmacSHAOps.asRight
      case algorithm: `RSASSA-PKCS1-v1_5Algorithm` => `RSASSA-PKCS1-v1_5Ops`.asRight
      case algorithm: `RSASSA-PSSAlgorithm` => `RSASSA-PSSOps`.asRight
      case algorithm: EdDSA => EdDSAOps.asRight
      case _ => UnsupportedSignatureAlgorithm(algorithm).asLeft
end SignatureOps
