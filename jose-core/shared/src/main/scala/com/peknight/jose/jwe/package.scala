package com.peknight.jose

import com.peknight.jose.jwx.JoseHeader

package object jwe:
  def mergedHeader(header: JoseHeader, sharedHeader: Option[JoseHeader], recipientHeader: Option[JoseHeader])
  : JoseHeader =
    val commonHeader = sharedHeader.fold(header)(_.deepMerge(header))
    recipientHeader.fold(commonHeader)(commonHeader.deepMerge)
end jwe
