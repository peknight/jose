package com.peknight.jose

import com.peknight.crypto.algorithm.NONE
import com.peknight.crypto.algorithm.mac.{HmacSHA256, HmacSHA384, HmacSHA512}
import com.peknight.crypto.algorithm.signature.*
import com.peknight.jose.jwa.Requirement.{Optional, Recommended, Required, `Recommended+`}

package object jwa:
  val HS256: HmacAlgorithm = HmacAlgorithm(HmacSHA256, Required)
  val HS384: HmacAlgorithm = HmacAlgorithm(HmacSHA384, Optional)
  val HS512: HmacAlgorithm = HmacAlgorithm(HmacSHA512, Optional)

  val RS256: RSAAlgorithm = RSAAlgorithm(SHA256withRSA, Recommended)
  val RS384: RSAAlgorithm = RSAAlgorithm(SHA384withRSA, Optional)
  val RS512: RSAAlgorithm = RSAAlgorithm(SHA512withRSA, Optional)

  val ES256: ECDSAAlgorithm = ECDSAAlgorithm(SHA256withECDSA, `Recommended+`)
  val ES384: ECDSAAlgorithm = ECDSAAlgorithm(SHA384withECDSA, Optional)
  val ES512: ECDSAAlgorithm = ECDSAAlgorithm(SHA512withECDSA, Optional)

  val PS256: RSA_PSSAlgorithm = RSA_PSSAlgorithm(SHA256withRSA_PSSandMGF1, Optional)
  val PS384: RSA_PSSAlgorithm = RSA_PSSAlgorithm(SHA384withRSA_PSSandMGF1, Optional)
  val PS512: RSA_PSSAlgorithm = RSA_PSSAlgorithm(SHA512withRSA_PSSandMGF1, Optional)

  val none: NONEAlgorithm.type = NONEAlgorithm
end jwa
