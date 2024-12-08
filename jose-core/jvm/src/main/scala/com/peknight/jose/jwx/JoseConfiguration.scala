package com.peknight.jose.jwx

import com.peknight.jose.jwa.encryption.KeyDecipherMode
import com.peknight.security.provider.Provider

import java.nio.charset.{Charset, StandardCharsets}
import java.security.{SecureRandom, Provider as JProvider}

case class JoseConfiguration(
                              doKeyValidation: Boolean = true,
                              useLegacyName: Boolean = false,
                              writeCekHeadersToRecipientHeader: Boolean = false,
                              skipSignatureVerification: Boolean = false,
                              skipVerificationKeyResolutionOnNone: Boolean = false,
                              liberalContentTypeHandling: Boolean = false,
                              requireSignature: Boolean = true,
                              requireEncryption: Boolean = false,
                              requireIntegrity: Boolean = false,
                              charset: Charset = StandardCharsets.UTF_8,
                              knownCriticalHeaders: List[String] = List.empty[String],
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
