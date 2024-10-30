package com.peknight.jose.jwx

import com.peknight.security.provider.Provider

import java.security.Provider as JProvider

case class ProviderContext(
                            cipherProvider: Option[Provider | JProvider] = None,
                            macProvider: Option[Provider | JProvider] = None,
                            messageDigestProvider: Option[Provider | JProvider] = None,
                            keyAgreementProvider: Option[Provider | JProvider] = None,
                            keyFactoryProvider: Option[Provider | JProvider] = None,
                            keyPairGeneratorProvider: Option[Provider | JProvider] = None,
                            signatureProvider: Option[Provider | JProvider] = None
                          ):
  def cipher(provider: Provider | JProvider): ProviderContext = copy(cipherProvider = Some(provider))
  def cipher(provider: Option[Provider | JProvider]): ProviderContext = copy(cipherProvider = provider)
  def mac(provider: Provider | JProvider): ProviderContext = copy(macProvider = Some(provider))
  def mac(provider: Option[Provider | JProvider]): ProviderContext = copy(macProvider = provider)
  def messageDigest(provider: Provider | JProvider): ProviderContext = copy(messageDigestProvider = Some(provider))
  def messageDigest(provider: Option[Provider | JProvider]): ProviderContext = copy(messageDigestProvider = provider)
  def keyAgreement(provider: Provider | JProvider): ProviderContext = copy(keyAgreementProvider = Some(provider))
  def keyAgreement(provider: Option[Provider | JProvider]): ProviderContext = copy(keyAgreementProvider = provider)
  def keyFactory(provider: Provider | JProvider): ProviderContext = copy(keyFactoryProvider = Some(provider))
  def keyFactory(provider: Option[Provider | JProvider]): ProviderContext = copy(keyFactoryProvider = provider)
  def keyPairGenerator(provider: Provider | JProvider): ProviderContext = copy(keyPairGeneratorProvider = Some(provider))
  def keyPairGenerator(provider: Option[Provider | JProvider]): ProviderContext = copy(keyPairGeneratorProvider = provider)
  def signature(provider: Provider | JProvider): ProviderContext = copy(signatureProvider = Some(provider))
  def signature(provider: Option[Provider | JProvider]): ProviderContext = copy(signatureProvider = provider)
end ProviderContext

object ProviderContext:
  val default = ProviderContext()
end ProviderContext
