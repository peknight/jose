package com.peknight.jose.jwe

import cats.Monad
import cats.data.{EitherT, NonEmptyList}
import cats.effect.{Async, Sync}
import cats.syntax.either.*
import com.peknight.cats.ext.syntax.eitherT.{eLiftET, rLiftET}
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.either.label
import com.peknight.jose.error.CanNotHaveKey
import com.peknight.jose.jwe.Recipient.Recipient
import com.peknight.jose.jwa.encryption.{EncryptionAlgorithm, KeyManagementAlgorithm}
import com.peknight.jose.jwx.{JoseConfiguration, JoseHeader}
import com.peknight.jose.{algorithmLabel, encryptionAlgorithmLabel}
import com.peknight.validation.collection.nonEmptyList.either.elementConsistent
import com.peknight.validation.std.either.typed
import fs2.compression.Compression
import scodec.bits.ByteVector

trait JsonWebEncryptionsCompanion:
  private def handleEncrypt[F[_]: Async: Compression](primitives: NonEmptyList[EncryptionPrimitive], header: JoseHeader,
                                                      plaintext: ByteVector, cekOverride: Option[ByteVector] = None,
                                                      ivOverride: Option[ByteVector] = None,
                                                      aadOverride: Option[ByteVector] = None,
                                                      sharedHeader: Option[JoseHeader] = None,
                                                      configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebEncryptions]] =
    val commonHeader = sharedHeader.fold(header)(_.deepMerge(header))
    for
      encryptionAlgorithm <- elementConsistent(primitives)(_.recipientHeader.flatMap(_.encryptionAlgorithm))
        .label(encryptionAlgorithmLabel).eLiftET[F]
      encryptionAlgorithm <- encryptionAlgorithm.orElse(commonHeader.encryptionAlgorithm)
        .toRight(OptionEmpty.label(encryptionAlgorithmLabel)).eLiftET[F]
      (cek, handledRecipientWithIndexOption, unhandledPrimitivesWithIndex) <- handleCek[F](primitives, commonHeader,
        encryptionAlgorithm, cekOverride)
    yield
      ()
    ???

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
              primitive.recipientHeader.fold(commonHeader)(commonHeader.deepMerge), encryptionAlgorithm, primitive.key,
              cekOverride, primitive.configuration)
            .map(contentEncryptionKeys => (
              contentEncryptionKeys.contentEncryptionKey,
              Some((Recipient(
                JsonWebEncryption.updateRecipientHeader(primitive.recipientHeader, contentEncryptionKeys),
                Base64UrlNoPad.fromByteVector(contentEncryptionKeys.contentEncryptionKey)
              ), index)),
              list
            ))
          }
  end handleCek

end JsonWebEncryptionsCompanion
