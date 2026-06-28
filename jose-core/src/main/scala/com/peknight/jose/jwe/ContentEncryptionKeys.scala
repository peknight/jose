package com.peknight.jose.jwe

import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.jose.jwe.Recipient.Recipient
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwx.JoseHeader
import scodec.bits.ByteVector

case class ContentEncryptionKeys(
                                  contentEncryptionKey: ByteVector,
                                  encryptedKey: ByteVector,
                                  ephemeralPublicKey: Option[JsonWebKey] = None,
                                  initializationVector: Option[ByteVector] = None,
                                  authenticationTag: Option[ByteVector] = None,
                                  pbes2SaltInput: Option[ByteVector] = None,
                                  pbes2Count: Option[Long] = None
                                ):
  def toHeader: Option[JoseHeader] =
    (ephemeralPublicKey, initializationVector, authenticationTag, pbes2SaltInput, pbes2Count) match
      case (None, None, None, None, None) => None
      case _ => Some(JoseHeader(
        ephemeralPublicKey = ephemeralPublicKey,
        initializationVector = initializationVector.map(Base64UrlNoPad.fromByteVector),
        authenticationTag = authenticationTag.map(Base64UrlNoPad.fromByteVector),
        pbes2SaltInput = pbes2SaltInput.map(Base64UrlNoPad.fromByteVector),
        pbes2Count = pbes2Count
      ))

  def updateHeader(header: JoseHeader): JoseHeader = header.copy(
    ephemeralPublicKey = ephemeralPublicKey.orElse(header.ephemeralPublicKey),
    initializationVector = initializationVector.map(Base64UrlNoPad.fromByteVector).orElse(header.initializationVector),
    authenticationTag = authenticationTag.map(Base64UrlNoPad.fromByteVector).orElse(header.authenticationTag),
    pbes2SaltInput = pbes2SaltInput.map(Base64UrlNoPad.fromByteVector).orElse(header.pbes2SaltInput),
    pbes2Count = pbes2Count.orElse(header.pbes2Count)
  )

  def updateHeader(recipientHeader: Option[JoseHeader]): Option[JoseHeader] =
    recipientHeader.fold(toHeader)(rh => Some(updateHeader(rh)))

  def toRecipient(recipientHeader: Option[JoseHeader]): Recipient =
    Recipient(updateHeader(recipientHeader), Base64UrlNoPad.fromByteVector(encryptedKey))
end ContentEncryptionKeys
