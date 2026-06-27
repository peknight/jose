package com.peknight.jose.jws

import cats.Id
import cats.effect.Sync
import com.peknight.codec.Encoder
import com.peknight.error.Error
import com.peknight.jose.jwx.{JoseConfig, JoseHeader, JosePrimitive}
import io.circe.Json
import scodec.bits.ByteVector

import java.security.Key

case class SigningPrimitive(header: JoseHeader, key: Option[Key] = None,
                            config: JoseConfig = JoseConfig.default) extends JosePrimitive
