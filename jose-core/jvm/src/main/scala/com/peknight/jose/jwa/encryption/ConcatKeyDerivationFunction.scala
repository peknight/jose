package com.peknight.jose.jwa.encryption

import cats.Foldable
import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.syntax.option.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.cats.instances.scodec.bits.byteVector.given
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwx.toBytes
import com.peknight.security.digest.MessageDigestAlgorithm
import com.peknight.security.provider.Provider
import com.peknight.security.syntax.messageDigest.{digestF, getDigestLengthF, updateF}
import fs2.Stream
import scodec.bits.ByteVector

import java.security.Provider as JProvider

object ConcatKeyDerivationFunction:
  def kdf[F[_]: Sync](messageDigestAlgorithm: MessageDigestAlgorithm, sharedSecret: ByteVector, cekLength: Int,
                      algorithm: Option[AlgorithmIdentifier], agreementPartyUInfo: Option[ByteVector],
                      agreementPartyVInfo: Option[ByteVector], provider: Option[Provider | JProvider]
                     ): F[Either[Error, ByteVector]] =

    val eitherT =
      for
        algorithmId <- algorithm.fold(none[ByteVector].asRight[Error])(enc => toBytes(enc.identifier).map(_.some))
          .eLiftET[F]
        derivedKey <- EitherT(kdf[F](messageDigestAlgorithm, sharedSecret,
          otherInfo(cekLength, algorithmId, agreementPartyUInfo, agreementPartyVInfo), cekLength, provider).asError)
      yield derivedKey
    eitherT.value

  private[encryption] def otherInfo(cekLength: Int, algorithmId: Option[ByteVector],
                                    agreementPartyUInfo: Option[ByteVector],
                                    agreementPartyVInfo: Option[ByteVector]
                                   ): ByteVector =
    val algorithmIdBytes = prependDataLength(algorithmId)
    val partyUInfoBytes = prependDataLength(agreementPartyUInfo)
    val partyVInfoBytes = prependDataLength(agreementPartyVInfo)
    val keyBitLength = cekLength * 8
    val suppPubInfo = ByteVector.fromInt(keyBitLength)
    val suppPrivInfo = ByteVector.empty
    algorithmIdBytes ++ partyUInfoBytes ++ partyVInfoBytes ++ suppPubInfo ++ suppPrivInfo

  private[encryption] def prependDataLength(data: Option[ByteVector]): ByteVector =
    data.fold(ByteVector.fromInt(0))(data => ByteVector.fromInt(data.length.toInt) ++ data)

  private[encryption] def kdf[F[_]: Sync](messageDigestAlgorithm: MessageDigestAlgorithm, sharedSecret: ByteVector,
                                          otherInfo: ByteVector, keyByteLength: Int,
                                          provider: Option[Provider | JProvider]
                                         ): F[ByteVector] =
    for
      messageDigest <- messageDigestAlgorithm.getMessageDigest[F](provider)
      digestLength <- messageDigest.getDigestLengthF[F]
      reps = getReps(keyByteLength * 8, digestLength * 8)
      digests <- Stream.emits(1 to reps).evalMap[F, ByteVector] { i =>
        val counterBytes = ByteVector.fromInt(i)
        for
          _ <- messageDigest.updateF[F](counterBytes)
          _ <- messageDigest.updateF[F](sharedSecret)
          _ <- messageDigest.updateF[F](otherInfo)
          digest <- messageDigest.digestF[F]
        yield
          digest
      }.compile.toList
    yield
      val derivedKeyMaterial = Foldable[List].fold[ByteVector](digests)
      if derivedKeyMaterial.length != keyByteLength then
        derivedKeyMaterial.take(keyByteLength)
      else derivedKeyMaterial

  private[encryption] def getReps(keyBitLength: Int, digestBitLength: Int): Int =
    val repsD: Double = keyBitLength.toFloat / digestBitLength.toFloat
    Math.ceil(repsD).toInt
end ConcatKeyDerivationFunction
