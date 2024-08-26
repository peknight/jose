package com.peknight.jose.jws

import com.peknight.security.provider.Provider

import java.security.{Key, Provider as JProvider}

case class VerifyPrimitive(key: Option[Key] = None, doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                           provider: Option[Provider | JProvider] = None)
