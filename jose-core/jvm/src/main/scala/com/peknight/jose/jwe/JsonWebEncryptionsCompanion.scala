package com.peknight.jose.jwe

import cats.data.{EitherT, NonEmptyList}
import cats.effect.{Async, Sync}
import cats.syntax.applicative.*
import cats.syntax.apply.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.syntax.parallel.*
import cats.syntax.traverse.*
import cats.{Id, Monad, Parallel}
import com.peknight.cats.ext.syntax.eitherT.{eLiftET, rLiftET}
import com.peknight.codec.Encoder
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.either.label
import com.peknight.jose.error.CanNotHaveKey
import com.peknight.jose.jwa.encryption.{EncryptionAlgorithm, KeyManagementAlgorithm}
import com.peknight.jose.jwe.Recipient.Recipient
import com.peknight.jose.jwx.{JoseConfig, JoseHeader, encodeToJsonBytes, stringEncodeToBytes}
import com.peknight.jose.{algorithmLabel, compressionAlgorithmLabel, encryptionAlgorithmLabel}
import com.peknight.validation.collection.nonEmptyList.either.elementConsistent
import com.peknight.validation.std.either.typed
import fs2.compression.Compression
import io.circe.Json
import scodec.bits.ByteVector

trait JsonWebEncryptionsCompanion:

  def encryptString[F[_]: {Async, Compression}](primitives: NonEmptyList[EncryptionPrimitive], header: JoseHeader,
                                                plaintextString: String, cekOverride: Option[ByteVector] = None,
                                                ivOverride: Option[ByteVector] = None,
                                                aadOverride: Option[ByteVector] = None,
                                                sharedHeader: Option[JoseHeader] = None,
                                                config: JoseConfig = JoseConfig.default)
  : F[Either[Error, JsonWebEncryptions]] =
    handleEncryptPlaintext[F](primitives, header, stringEncodeToBytes(plaintextString, config.charset), cekOverride,
      ivOverride, aadOverride, sharedHeader, config)(_.sequence)((_, _).tupled)

  def encryptJson[F[_], A](primitives: NonEmptyList[EncryptionPrimitive], header: JoseHeader,
                           plaintextValue: A, cekOverride: Option[ByteVector] = None,
                           ivOverride: Option[ByteVector] = None,
                           aadOverride: Option[ByteVector] = None,
                           sharedHeader: Option[JoseHeader] = None,
                           config: JoseConfig = JoseConfig.default)
                          (using Async[F], Compression[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebEncryptions]] =
    handleEncryptPlaintext[F](primitives, header, encodeToJsonBytes(plaintextValue, config.charset), cekOverride,
      ivOverride, aadOverride, sharedHeader, config)(_.sequence)((_, _).tupled)

  def parEncryptString[F[_]: {Async, Compression, Parallel}](primitives: NonEmptyList[EncryptionPrimitive],
                                                             header: JoseHeader, plaintextString: String,
                                                             cekOverride: Option[ByteVector] = None,
                                                             ivOverride: Option[ByteVector] = None,
                                                             aadOverride: Option[ByteVector] = None,
                                                             sharedHeader: Option[JoseHeader] = None,
                                                             config: JoseConfig = JoseConfig.default)
  : F[Either[Error, JsonWebEncryptions]] =
    handleEncryptPlaintext[F](primitives, header, stringEncodeToBytes(plaintextString, config.charset), cekOverride,
      ivOverride, aadOverride, sharedHeader, config)(_.parSequence)((_, _).parTupled)

  def parEncryptJson[F[_], A](primitives: NonEmptyList[EncryptionPrimitive], header: JoseHeader,
                              plaintextValue: A, cekOverride: Option[ByteVector] = None,
                              ivOverride: Option[ByteVector] = None,
                              aadOverride: Option[ByteVector] = None,
                              sharedHeader: Option[JoseHeader] = None,
                              config: JoseConfig = JoseConfig.default)
                             (using Async[F], Compression[F], Parallel[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebEncryptions]] =
    handleEncryptPlaintext[F](primitives, header, encodeToJsonBytes(plaintextValue, config.charset), cekOverride,
      ivOverride, aadOverride, sharedHeader, config)(_.parSequence)((_, _).parTupled)

  private def handleEncryptPlaintext[F[_]: {Async, Compression}](primitives: NonEmptyList[EncryptionPrimitive],
                                                                 header: JoseHeader,
                                                                 plaintextEither: Either[Error, ByteVector],
                                                                 cekOverride: Option[ByteVector],
                                                                 ivOverride: Option[ByteVector],
                                                                 aadOverride: Option[ByteVector],
                                                                 sharedHeader: Option[JoseHeader],
                                                                 config: JoseConfig)
                                                                (sequence: List[F[Either[Error, (Recipient, Int)]]] => F[List[Either[Error, (Recipient, Int)]]])
                                                                (tupled: (F[Either[Error, List[Recipient]]], F[Either[Error, (ContentEncryptionParts, Base64UrlNoPad)]]) => F[(Either[Error, List[Recipient]], Either[Error, (ContentEncryptionParts, Base64UrlNoPad)])])
  : F[Either[Error, JsonWebEncryptions]] =
    plaintextEither match
      case Left(error) => error.asLeft[JsonWebEncryptions].pure[F]
      case Right(plaintext) => handleEncrypt[F](primitives, header, plaintext, cekOverride, ivOverride, aadOverride,
        sharedHeader, config)(sequence)(tupled)

  def encrypt[F[_]: {Async, Compression}](primitives: NonEmptyList[EncryptionPrimitive], header: JoseHeader,
                                          plaintext: ByteVector, cekOverride: Option[ByteVector] = None,
                                          ivOverride: Option[ByteVector] = None,
                                          aadOverride: Option[ByteVector] = None,
                                          sharedHeader: Option[JoseHeader] = None,
                                          config: JoseConfig = JoseConfig.default)
  : F[Either[Error, JsonWebEncryptions]] =
    handleEncrypt[F](
      primitives, header, plaintext, cekOverride, ivOverride, aadOverride, sharedHeader, config
    )(_.sequence)((_, _).tupled)

  def parEncrypt[F[_]: {Async, Compression, Parallel}](primitives: NonEmptyList[EncryptionPrimitive], header: JoseHeader,
                                                       plaintext: ByteVector, cekOverride: Option[ByteVector] = None,
                                                       ivOverride: Option[ByteVector] = None,
                                                       aadOverride: Option[ByteVector] = None,
                                                       sharedHeader: Option[JoseHeader] = None,
                                                       config: JoseConfig = JoseConfig.default)
  : F[Either[Error, JsonWebEncryptions]] =
    handleEncrypt[F](
      primitives, header, plaintext, cekOverride, ivOverride, aadOverride, sharedHeader, config
    )(_.parSequence)((_, _).parTupled)

  private def handleEncrypt[F[_]: {Async, Compression}](primitives: NonEmptyList[EncryptionPrimitive], header: JoseHeader,
                                                        plaintext: ByteVector, cekOverride: Option[ByteVector],
                                                        ivOverride: Option[ByteVector], aadOverride: Option[ByteVector],
                                                        sharedHeader: Option[JoseHeader], config: JoseConfig)
                                                       (sequence: List[F[Either[Error, (Recipient, Int)]]] => F[List[Either[Error, (Recipient, Int)]]])
                                                       (tupled: (F[Either[Error, List[Recipient]]], F[Either[Error, (ContentEncryptionParts, Base64UrlNoPad)]]) => F[(Either[Error, List[Recipient]], Either[Error, (ContentEncryptionParts, Base64UrlNoPad)])])
  : F[Either[Error, JsonWebEncryptions]] =
    val commonHeader = mergedCommonHeader(header, sharedHeader)
    val eitherT =
      for
        encryptionAlgorithm <- elementConsistent(primitives)(_.recipientHeader.flatMap(_.encryptionAlgorithm))
          .label(encryptionAlgorithmLabel).eLiftET[F]
        encryptionAlgorithm <- encryptionAlgorithm.orElse(commonHeader.encryptionAlgorithm)
          .toRight(OptionEmpty.label(encryptionAlgorithmLabel)).eLiftET[F]
        compressionAlgorithm <- elementConsistent(primitives)(_.recipientHeader.flatMap(_.compressionAlgorithm))
          .label(compressionAlgorithmLabel).eLiftET[F]
        (contentEncryptionKey, handledRecipientWithIndexOption, unhandledPrimitivesWithIndex) <- handleCek[F](primitives,
          commonHeader, encryptionAlgorithm, cekOverride)
        recipientsF = sequence(unhandledPrimitivesWithIndex.map((primitive, index) =>
          JsonWebEncryption.handleEncryptKey[F](mergedRecipientHeader(commonHeader, primitive.recipientHeader),
              encryptionAlgorithm, primitive.key, Some(contentEncryptionKey), primitive.config)
            .map(contentEncryptionKeys => (contentEncryptionKeys.toRecipient(primitive.recipientHeader), index))
            .value
        )).map(_.sequence.map(list => handledRecipientWithIndexOption.fold(list)(_ :: list).sortBy(_._2).map(_._1)))
        contentEncryptionPartsAndAADF = JsonWebEncryption.handleEncrypt[F](header, encryptionAlgorithm,
          compressionAlgorithm.orElse(commonHeader.compressionAlgorithm), plaintext, contentEncryptionKey, ivOverride,
          aadOverride, config).value
        jsonWebEncryptions <- EitherT(tupled(recipientsF, contentEncryptionPartsAndAADF)
          .map((recipientsE, contentEncryptionPartsAndAADE) =>
            for
              recipients <- recipientsE
              (contentEncryptionParts, aad) <- contentEncryptionPartsAndAADE
            yield
              JsonWebEncryptions(header, sharedHeader, NonEmptyList.fromListUnsafe(recipients),
                Base64UrlNoPad.fromByteVector(contentEncryptionParts.initializationVector),
                Base64UrlNoPad.fromByteVector(contentEncryptionParts.ciphertext),
                Base64UrlNoPad.fromByteVector(contentEncryptionParts.authenticationTag),
                Some(aad)
              ))
        )
      yield
        jsonWebEncryptions
    eitherT.value

  private def handleCek[F[_]: Sync](primitives: NonEmptyList[EncryptionPrimitive], commonHeader: JoseHeader,
                                    encryptionAlgorithm: EncryptionAlgorithm, cekOverride: Option[ByteVector])
  : EitherT[F, Error, (ByteVector, Option[(Recipient, Int)], List[(EncryptionPrimitive, Int)])] =
    val primitivesWithIndex = primitives.toList.zipWithIndex
    cekOverride match
      case Some(cek) => (cek, None, primitivesWithIndex).rLiftET[F, Error]
      case None =>
        type PrimitiveIndex = (EncryptionPrimitive, Int)
        type PrimitiveIndexOption = Option[PrimitiveIndex]
        type PrimitiveIndexList = List[PrimitiveIndex]
        type PrimitiveIndexTuple = (PrimitiveIndexOption, PrimitiveIndexList)
        Monad[[X] =>> Either[Error, X]]
          .tailRecM[(PrimitiveIndexList, PrimitiveIndexTuple), (PrimitiveIndex, PrimitiveIndexList)](
            (primitivesWithIndex.reverse, (None, Nil))
          ) {
            case (Nil, (Some(primitiveIndex), list)) =>
              (primitiveIndex, list).asRight[(PrimitiveIndexList, PrimitiveIndexTuple)].asRight[Error]
            case (Nil, (_, acc)) =>
              (acc.head, acc.tail).asRight[(PrimitiveIndexList, PrimitiveIndexTuple)].asRight[Error]
            case ((current, index) :: tail, (opt, acc)) =>
              current.recipientHeader
                .flatMap(_.algorithm)
                .orElse(commonHeader.algorithm)
                .toRight(OptionEmpty.label(algorithmLabel))
                .flatMap(typed[KeyManagementAlgorithm])
                .flatMap { algorithm =>
                  if algorithm.canOverrideCek then
                    (tail, (opt, (current, index) :: acc)).asLeft[(PrimitiveIndex, PrimitiveIndexList)].asRight[Error]
                  else
                    opt match
                      case Some(_) => CanNotHaveKey(algorithm).asLeft
                      case None =>
                        (tail, (Some((current, index)), acc)).asLeft[(PrimitiveIndex, PrimitiveIndexList)].asRight[Error]
                }
          }
          .eLiftET[F]
          .flatMap { case ((primitive, index), list) => JsonWebEncryption
            .handleEncryptKey[F](
              mergedRecipientHeader(commonHeader, primitive.recipientHeader), encryptionAlgorithm, primitive.key,
              cekOverride, primitive.config)
            .map(contentEncryptionKeys => (contentEncryptionKeys.contentEncryptionKey,
              Some((contentEncryptionKeys.toRecipient(primitive.recipientHeader), index)), list))
          }
  end handleCek

end JsonWebEncryptionsCompanion
