package com.peknight.jose.jwk.ops

import cats.effect.Sync
import com.peknight.security.key.factory.KeyFactoryAlgorithm
import com.peknight.security.key.pair.KeyPairGeneratorAlgorithm
import com.peknight.security.provider.Provider
import com.peknight.security.{KeyFactory, KeyPairGenerator}

import java.security.spec.{AlgorithmParameterSpec, KeySpec}
import java.security.{KeyPair, PrivateKey, PublicKey, SecureRandom, Provider as JProvider}

trait KeyPairOps:
  def keyAlgorithm: KeyFactoryAlgorithm & KeyPairGeneratorAlgorithm

  def keySizeGenerateKeyPair[F[_]: Sync](keySize: Int, provider: Option[Provider | JProvider] = None,
                                         random: Option[SecureRandom] = None): F[KeyPair] =
    KeyPairGenerator.keySizeGenerateKeyPair[F](keyAlgorithm, keySize, provider, random)
    
  def paramsGenerateKeyPair[F[_]: Sync](params: AlgorithmParameterSpec, provider: Option[Provider | JProvider] = None,
                                        random: Option[SecureRandom] = None): F[KeyPair] =
    KeyPairGenerator.paramsGenerateKeyPair[F](keyAlgorithm, params, provider, random)

  def generatePublic[F[_]: Sync](keySpec: KeySpec, provider: Option[Provider | JProvider] = None): F[PublicKey] =
    KeyFactory.generatePublic[F](keyAlgorithm, keySpec, provider)

  def generatePrivate[F[_]: Sync](keySpec: KeySpec, provider: Option[Provider | JProvider] = None): F[PrivateKey] =
    KeyFactory.generatePrivate[F](keyAlgorithm, keySpec, provider)
end KeyPairOps
