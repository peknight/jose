package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.{Foldable, Monad}
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.cats.instances.scodec.bits.byteVector.given
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.{asError, label, message}
import com.peknight.jose.error.MissingKey
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwe.ContentEncryptionKeys
import com.peknight.security.cipher.{AES, BlockCipher}
import com.peknight.security.mac.{Hmac, MACAlgorithm}
import com.peknight.security.provider.Provider
import com.peknight.security.spec.{SecretKeySpec, SecretKeySpecAlgorithm}
import com.peknight.security.syntax.mac.{doFinalF, getMacLengthF, initF}
import com.peknight.validation.spire.math.interval.either.{atOrAbove, atOrBelow}
import fs2.Stream
import scodec.bits.ByteVector

import java.security.{Key, PublicKey, SecureRandom, Provider as JProvider}
import javax.crypto.Mac

trait PBES2AlgorithmPlatform { self: PBES2Algorithm =>
  private val defaultIterationCount: Long = 8192L * 8
  private val defaultSaltByteLength: Int = 12
  private val maxIterationCount: Long = 2499999L
  def encryptKey[F[_]: Sync](managementKey: Key,
                             cekLength: Int,
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             cekOverride: Option[ByteVector] = None,
                             encryptionAlgorithm: Option[EncryptionAlgorithm] = None,
                             agreementPartyUInfo: Option[ByteVector] = None,
                             agreementPartyVInfo: Option[ByteVector] = None,
                             initializationVector: Option[ByteVector] = None,
                             pbes2SaltInput: Option[ByteVector] = None,
                             pbes2Count: Option[Long] = None,
                             random: Option[SecureRandom] = None,
                             cipherProvider: Option[Provider | JProvider] = None,
                             keyAgreementProvider: Option[Provider | JProvider] = None,
                             keyPairGeneratorProvider: Option[Provider | JProvider] = None,
                             macProvider: Option[Provider | JProvider] = None,
                             messageDigestProvider: Option[Provider | JProvider] = None
                            ): F[Either[Error, ContentEncryptionKeys]] =
    val eitherT =
      for
        (derivedKey, saltInput, iterationCount) <- deriveForEncrypt[F](self, self.encryption, self.prf, managementKey,
          AES, pbes2SaltInput, pbes2Count, random, macProvider)
        ContentEncryptionKeys(contentEncryptionKey, encryptedKey, _, _, _, _, _) <- EitherT(self.encryption.encryptKey[F](
          derivedKey, cekLength, cekAlgorithm, cekOverride, encryptionAlgorithm, agreementPartyUInfo,
          agreementPartyVInfo, initializationVector, Some(saltInput), Some(iterationCount), random, cipherProvider,
          keyAgreementProvider, keyPairGeneratorProvider, macProvider, messageDigestProvider))
      yield
        ContentEncryptionKeys(contentEncryptionKey, encryptedKey, pbes2SaltInput = Some(saltInput),
          pbes2Count = Some(iterationCount))
    eitherT.value

  def decryptKey[F[_]: Sync](managementKey: Key,
                             encryptedKey: ByteVector,
                             cekLength: Int,
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                             encryptionAlgorithm: Option[EncryptionAlgorithm] = None,
                             ephemeralPublicKey: Option[PublicKey] = None,
                             agreementPartyUInfo: Option[ByteVector] = None,
                             agreementPartyVInfo: Option[ByteVector] = None,
                             initializationVector: Option[ByteVector] = None,
                             authenticationTag: Option[ByteVector] = None,
                             pbes2SaltInput: Option[ByteVector] = None,
                             pbes2Count: Option[Long] = None,
                             random: Option[SecureRandom] = None,
                             cipherProvider: Option[Provider | JProvider] = None,
                             keyAgreementProvider: Option[Provider | JProvider] = None,
                             macProvider: Option[Provider | JProvider] = None,
                             messageDigestProvider: Option[Provider | JProvider] = None
                            ): F[Either[Error, Key]] =
    val eitherT =
      for
        pbes2Count <- pbes2Count.toRight(OptionEmpty.label("pbes2Count")).eLiftET
        pbes2SaltInput <- pbes2SaltInput.toRight(OptionEmpty.label("pbes2SlatInput")).eLiftET
        iterationCount <- atOrBelow(pbes2Count, maxIterationCount)
          .message(s"PBES2 iteration count (p2c=$pbes2Count) cannot be more than $maxIterationCount to avoid " +
            s"excessive resource utilization.")
          .eLiftET
        derivedKey <- deriveKey(self, self.encryption, self.prf, managementKey, AES, iterationCount.toInt, pbes2SaltInput,
          macProvider)
        key <- EitherT(self.encryption.decryptKey[F](derivedKey, encryptedKey, cekLength, cekAlgorithm,
          keyDecipherModeOverride, encryptionAlgorithm, ephemeralPublicKey, agreementPartyUInfo, agreementPartyVInfo,
          initializationVector, authenticationTag, Some(pbes2SaltInput), Some(pbes2Count), random, cipherProvider,
          keyAgreementProvider, macProvider, messageDigestProvider))
      yield
        key
    eitherT.value

  private def deriveForEncrypt[F[_]: Sync](identifier: AlgorithmIdentifier, cipher: BlockCipher, prf: MACAlgorithm,
                                           managementKey: Key, cekAlgorithm: SecretKeySpecAlgorithm,
                                           pbes2SaltInput: Option[ByteVector], pbes2Count: Option[Long] = None,
                                           random: Option[SecureRandom] = None,
                                           macProvider: Option[Provider | JProvider] = None
                                          ): EitherT[F, Error, (Key, ByteVector, Long)] =
    for
      iterationCount <- atOrAbove(pbes2Count.getOrElse(defaultIterationCount), 1000L).label("iterationCount").eLiftET
      saltInput <- EitherT(getBytesOrRandom[F](pbes2SaltInput.toRight(defaultSaltByteLength), random).asError)
      _ <- atOrAbove(saltInput.length, 8L).label("saltInput").eLiftET
      derivedKey <- deriveKey[F](identifier, cipher, prf, managementKey, cekAlgorithm, iterationCount.toInt, saltInput,
        macProvider)
    yield
      (derivedKey, saltInput, iterationCount)

  private def deriveKey[F[_]: Sync](identifier: AlgorithmIdentifier, cipher: BlockCipher, prf: MACAlgorithm,
                                    managementKey: Key, cekAlgorithm: SecretKeySpecAlgorithm, iterationCount: Int,
                                    saltInput: ByteVector, provider: Option[Provider | JProvider] = None)
  : EitherT[F, Error, Key] =
    for
      identifierBytes <- ByteVector.encodeUtf8(identifier.identifier).asError.eLiftET
      salt = identifierBytes ++ (0 +: saltInput)
      dkLen = cipher.blockSize
      derivedKeyBytes <- derive[F](prf, ByteVector(managementKey.getEncoded), salt, iterationCount, dkLen, provider)
    yield
      SecretKeySpec(derivedKeyBytes, cekAlgorithm)

  private def derive[F[_]: Sync](prf: MACAlgorithm, password: ByteVector, salt: ByteVector, iterationCount: Int,
                                 dkLen: Int, provider: Option[Provider | JProvider] = None)
  : EitherT[F, Error, ByteVector] =
    for
      prf <- EitherT(prf.getMAC[F](provider).asError)
      _ <- EitherT(prf.initF[F](SecretKeySpec(password, Hmac)).asError)
      hLen <- EitherT(prf.getMacLengthF[F].asError)
      //  1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
      //     stop.
      // value of (Math.pow(2, 32) - 1).toLong
      maxDerivedKeyLength = 4294967295L
      _ <- atOrBelow(dkLen.toLong, maxDerivedKeyLength).label("derivedKey").eLiftET
      //  2. Let l be the number of hLen-octet blocks in the derived key,
      //     rounding up, and let r be the number of octets in the last
      //     block:
      //
      //               l = CEIL (dkLen / hLen) ,
      //               r = dkLen - (l - 1) * hLen .
      //
      //     Here, CEIL (x) is the "ceiling" function, i.e. the smallest
      //     integer greater than, or equal to, x.
      l = Math.ceil(dkLen.toDouble / hLen.toDouble).toInt
      r = dkLen - (l - 1) * hLen
      //  3. For each block of the derived key apply the function F defined
      //     below to the password P, the salt S, the iteration count c, and
      //     the block index to compute the block:
      //
      //               T_1 = F (P, S, c, 1) ,
      //               T_2 = F (P, S, c, 2) ,
      //               ...
      //               T_l = F (P, S, c, l) ,
      //
      //     where the function F is defined as the exclusive-or sum of the
      //     first c iterates of the underlying pseudorandom function PRF
      //     applied to the password P and the concatenation of the salt S
      //     and the block index i:
      //
      //               F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
      //
      //     where
      //
      //               U_1 = PRF (P, S || INT (i)) ,
      //               U_2 = PRF (P, U_1) ,
      //               ...
      //               U_c = PRF (P, U_{c-1}) .
      //
      //     Here, INT (i) is a four-octet encoding of the integer i, most
      //     significant octet first.
      //  4. Concatenate the blocks and extract the first dkLen octets to
      //     produce a derived key DK:
      //
      //               DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
      //
      byteVectors <- EitherT(Stream.emits(0 until l).evalMap[F, ByteVector] { i =>
        derive[F](salt, iterationCount, i + 1, prf).map(block => if i == l - 1 then block.take(r) else block)
      }.compile.toList.asError)
    yield
      //  5. Output the derived key DK.
      Foldable[List].fold[ByteVector](byteVectors)

  private def derive[F[_]: Sync](salt: ByteVector, iterationCount: Int, blockIndex: Int, prf: Mac): F[ByteVector] =
    prf.doFinalF[F](salt ++ ByteVector.fromInt(blockIndex)).flatMap { currentU =>
      val currentUBytes = currentU.toArray
      Monad[F].tailRecM[(Int, Array[Byte], Array[Byte]), ByteVector]((2, currentUBytes, currentUBytes)) {
        case (i, _, xorU) if i > iterationCount => ByteVector(xorU).asRight.pure
        case (i, lastU, xorU) =>
          Sync[F].blocking(prf.doFinal(lastU)).map(currentU => (i + 1, currentU, xor(currentU, xorU)).asLeft)
      }
    }

  private def xor(a: Array[Byte], b: Array[Byte]): Array[Byte] =
    for i <- a.indices do b(i) = (a(i) ^ b(i)).toByte
    b

  def validateEncryptionKey(managementKey: Key, cekLength: Int): Either[Error, Unit] = validateKey(managementKey)

  def validateDecryptionKey(managementKey: Key, cekLength: Int): Either[Error, Unit] = validateKey(managementKey)

  def validateKey(managementKey: Key): Either[Error, Unit] =
    Option(managementKey).toRight(MissingKey.label("managementKey")).as(())

  def isAvailable[F[_]: Sync]: F[Boolean] = self.encryption.isAvailable[F]
}
