package com.peknight.jose.key

import cats.effect.Sync
import cats.syntax.flatMap.*
import com.peknight.security.KeyFactory
import com.peknight.security.key.factory.KeyFactoryAlgorithm
import com.peknight.security.key.pair.KeyPairGeneratorAlgorithm
import com.peknight.security.provider.Provider
import com.peknight.security.syntax.keyFactory.{generatePrivateF, generatePublicF}

import java.security.spec.KeySpec
import com.peknight.security.KeyPairGenerator
import java.security.{KeyPairGenerator as JKeyPairGenerator, PrivateKey, PublicKey, KeyFactory as JKeyFactory}

trait KeyPairOps:
  def keyAlgorithm: KeyFactoryAlgorithm & KeyPairGeneratorAlgorithm

  def keyFactory[F[_]: Sync](provider: Option[Provider] = None): F[JKeyFactory] =
    KeyFactory.getInstance[F](keyAlgorithm, provider)

  def keyPairGenerator[F[_]: Sync](provider: Option[Provider] = None): F[JKeyPairGenerator] =
    KeyPairGenerator.getInstance[F](keyAlgorithm, provider)

  def generatePublicKey[F[_]: Sync](keySpec: KeySpec, provider: Option[Provider] = None): F[PublicKey] =
    keyFactory[F](provider).flatMap(factory => factory.generatePublicF[F](keySpec))

  def generatePrivateKey[F[_]: Sync](keySpec: KeySpec, provider: Option[Provider] = None): F[PrivateKey] =
    keyFactory[F](provider).flatMap(factory => factory.generatePrivateF[F](keySpec))
end KeyPairOps
