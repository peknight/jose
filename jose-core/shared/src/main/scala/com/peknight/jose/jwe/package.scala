package com.peknight.jose

import com.peknight.jose.jwx.JoseHeader

package object jwe:
  def mergedHeader(header: JoseHeader, sharedHeader: Option[JoseHeader], recipientHeader: Option[JoseHeader]): JoseHeader =
    val hs = sharedHeader.fold(header)(_.deepMerge(header))
    recipientHeader.fold(hs)(hs.deepMerge)
end jwe
