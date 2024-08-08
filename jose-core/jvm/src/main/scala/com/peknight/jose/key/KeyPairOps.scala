package com.peknight.jose.key

import cats.effect.Sync
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.security.KeyFactory
import com.peknight.security.key.factory.KeyFactoryAlgorithm
import com.peknight.security.provider.Provider
import com.peknight.security.syntax.keyFactory.{generatePrivateF, generatePublicF}

import java.security.spec.KeySpec
import java.security.{PrivateKey, PublicKey, KeyFactory as JKeyFactory}

trait KeyPairOps:
  def keyFactoryAlgorithm: KeyFactoryAlgorithm

  def keyFactory[F[_]: Sync](provider: Option[Provider]): F[JKeyFactory] =
    KeyFactory.getInstance[F](keyFactoryAlgorithm, provider)

  def generatePublicKey[F[_]: Sync, PublicK <: PublicKey](keySpec: KeySpec, provider: Option[Provider]): F[PublicK] =
    keyFactory[F](provider).flatMap(factory => factory.generatePublicF[F](keySpec)).map(_.asInstanceOf[PublicK])

  def generatePrivateKey[F[_]: Sync, PrivateK <: PrivateKey](keySpec: KeySpec, provider: Option[Provider]): F[PrivateK] =
    keyFactory[F](provider).flatMap(factory => factory.generatePrivateF[F](keySpec)).map(_.asInstanceOf[PrivateK])
end KeyPairOps
