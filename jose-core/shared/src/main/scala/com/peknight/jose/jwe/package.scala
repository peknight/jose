package com.peknight.jose

import com.peknight.jose.jwx.JoseHeader

package object jwe:
  def mergedHeader(header: JoseHeader, sharedHeader: Option[JoseHeader], recipientHeader: Option[JoseHeader])
  : JoseHeader =
    val commonHeader = mergedCommonHeader(header, sharedHeader)
    mergedRecipientHeader(commonHeader, recipientHeader)

  def mergedCommonHeader(header: JoseHeader, sharedHeader: Option[JoseHeader]): JoseHeader =
    sharedHeader.fold(header)(_.deepMerge(header))

  def mergedRecipientHeader(commonHeader: JoseHeader, recipientHeader: Option[JoseHeader]): JoseHeader =
    recipientHeader.fold(commonHeader)(commonHeader.deepMerge)

  def updateHeader(header: JoseHeader, recipientHeader: Option[JoseHeader],
                   contentEncryptionKeys: ContentEncryptionKeys, writeCekHeadersToRecipientHeader: Boolean)
  : (JoseHeader, Option[JoseHeader]) =
    if writeCekHeadersToRecipientHeader then (header, contentEncryptionKeys.updateHeader(recipientHeader))
    else (contentEncryptionKeys.updateHeader(header), recipientHeader)
end jwe
