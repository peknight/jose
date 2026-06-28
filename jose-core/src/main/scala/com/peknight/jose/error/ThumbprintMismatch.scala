package com.peknight.jose.error

import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.security.digest.MessageDigestAlgorithm

trait ThumbprintMismatch extends JoseError:
  def algorithm: MessageDigestAlgorithm
  def expectedThumbprint: Base64UrlNoPad
  def actualThumbprint: Option[Base64UrlNoPad]
  override protected def lowPriorityMessage: Option[String] =
    Some(s"${algorithm.algorithm} thumbprint mismatch: expect ${expectedThumbprint.value} got ${actualThumbprint.fold("none")(_.value)}")
end ThumbprintMismatch
object ThumbprintMismatch:
  private case class ThumbprintMismatch(algorithm: MessageDigestAlgorithm, expectedThumbprint: Base64UrlNoPad,
                                        actualThumbprint: Option[Base64UrlNoPad])
    extends com.peknight.jose.error.ThumbprintMismatch
  def apply(algorithm: MessageDigestAlgorithm, expectedThumbprint: Base64UrlNoPad,
            actualThumbprint: Option[Base64UrlNoPad]) : com.peknight.jose.error.ThumbprintMismatch =
    ThumbprintMismatch(algorithm, expectedThumbprint, actualThumbprint)
end ThumbprintMismatch
