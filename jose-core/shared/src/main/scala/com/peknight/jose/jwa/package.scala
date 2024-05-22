package com.peknight.jose

import com.peknight.crypto.algorithm.cipher.asymmetric.RSA
import com.peknight.crypto.algorithm.cipher.mgf.MGF1
import com.peknight.crypto.algorithm.cipher.mode.{CBC, GCM, GCMKW}
import com.peknight.crypto.algorithm.cipher.padding.{OAEP, OAEPWithDigestAndMGFPadding}
import com.peknight.crypto.algorithm.cipher.symmetric.*
import com.peknight.crypto.algorithm.digest.`SHA-256`
import com.peknight.crypto.algorithm.key.agreement.{`ECDH-ESWithAESWrap_128`, `ECDH-ESWithAESWrap_192`, `ECDH-ESWithAESWrap_256`}
import com.peknight.crypto.algorithm.mac.{HmacSHA256, HmacSHA384, HmacSHA512}
import com.peknight.crypto.algorithm.pbe.{PBES2withHmacSHA256andAESWrap_128, PBES2withHmacSHA384andAESWrap_192, PBES2withHmacSHA512andAESWrap_256}
import com.peknight.crypto.algorithm.signature.*
import Requirement.{Optional, Recommended, Required, `Recommended+`}

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


  val RSA1_5: RSA1_5Algorithm.type = RSA1_5Algorithm

  val `RSA-OAEP`: RSAOAEPAlgorithm = RSAOAEPAlgorithm(RSA / OAEP, `Recommended+`)
  val `RSA-OAEP-256`: RSAOAEPAlgorithm =
    RSAOAEPAlgorithm(RSA / OAEPWithDigestAndMGFPadding(`SHA-256`, MGF1), `Recommended+`)

  val A128KW: AESKeyWrapAlgorithm = AESKeyWrapAlgorithm(AESWrap_128, Recommended)
  val A192KW: AESKeyWrapAlgorithm = AESKeyWrapAlgorithm(AESWrap_192, Recommended)
  val A256KW: AESKeyWrapAlgorithm = AESKeyWrapAlgorithm(AESWrap_256, Recommended)

  val dir: DirectAlgorithm.type = DirectAlgorithm

  val `ECDH-ES`: ECDHESAlgorithm = ECDHESAlgorithm
  val `ECDH-ES+A128KW`: ECDHESAlgorithm = ECDHESAlgorithm(`ECDH-ESWithAESWrap_128`, Recommended)
  val `ECDH-ES+A192KW`: ECDHESAlgorithm = ECDHESAlgorithm(`ECDH-ESWithAESWrap_192`, Optional)
  val `ECDH-ES+A256KW`: ECDHESAlgorithm = ECDHESAlgorithm(`ECDH-ESWithAESWrap_256`, Recommended)

  val A128GCMKW: AESGCMKWAlgorithm = AESGCMKWAlgorithm(AES_128 / GCMKW)
  val A192GCMKW: AESGCMKWAlgorithm = AESGCMKWAlgorithm(AES_192 / GCMKW)
  val A256GCMKW: AESGCMKWAlgorithm = AESGCMKWAlgorithm(AES_256 / GCMKW)

  val `PBES2-HS256+A128KW`: PBES2Algorithm = PBES2Algorithm(PBES2withHmacSHA256andAESWrap_128)
  val `PBES2-HS384+A192KW`: PBES2Algorithm = PBES2Algorithm(PBES2withHmacSHA384andAESWrap_192)
  val `PBES2-HS512+A256KW`: PBES2Algorithm = PBES2Algorithm(PBES2withHmacSHA512andAESWrap_256)


  val `A128CBC-HS256`: AESCBCHmacSHA2Algorithm = AESCBCHmacSHA2Algorithm((AES_128 / CBC).withMAC(HmacSHA256), Required)
  val `A192CBC-HS384`: AESCBCHmacSHA2Algorithm = AESCBCHmacSHA2Algorithm((AES_192 / CBC).withMAC(HmacSHA384), Optional)
  val `A256CBC-HS512`: AESCBCHmacSHA2Algorithm = AESCBCHmacSHA2Algorithm((AES_256 / CBC).withMAC(HmacSHA512), Required)

  val A128GCM: AESGCMAlgorithm = AESGCMAlgorithm(AES_128 / GCM, Recommended)
  val A192GCM: AESGCMAlgorithm = AESGCMAlgorithm(AES_192 / GCM, Optional)
  val A256GCM: AESGCMAlgorithm = AESGCMAlgorithm(AES_256 / GCM, Recommended)
end jwa
