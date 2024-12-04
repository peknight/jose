package com.peknight.jose.jwx

import com.peknight.jose.jwa.encryption.KeyDecipherMode
import com.peknight.security.provider.Provider
import scodec.bits.ByteVector

import java.nio.charset.{Charset, StandardCharsets}
import java.security.{SecureRandom, Provider as JProvider}

case class JoseConfiguration(
                              doKeyValidation: Boolean = true,
                              useLegacyName: Boolean = false,
                              skipSignatureVerification: Boolean = false,
                              skipVerificationKeyResolutionOnNone: Boolean = false,
                              liberalContentTypeHandling: Boolean = false,
                              charset: Charset = StandardCharsets.UTF_8,
                              knownCriticalHeaders: List[String] = List.empty[String],
                              cekOverride: Option[ByteVector] = None,
                              ivOverride: Option[ByteVector] = None,
                              keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                              random: Option[SecureRandom] = None,
                              cipherProvider: Option[Provider | JProvider] = None,
                              keyAgreementProvider: Option[Provider | JProvider] = None,
                              keyFactoryProvider: Option[Provider | JProvider] = None,
                              keyPairGeneratorProvider: Option[Provider | JProvider] = None,
                              macProvider: Option[Provider | JProvider] = None,
                              messageDigestProvider: Option[Provider | JProvider] = None,
                              signatureProvider: Option[Provider | JProvider] = None
                            )
object JoseConfiguration:
  val default: JoseConfiguration = JoseConfiguration()
end JoseConfiguration
