package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.Opmode

enum KeyDecipherMode(val opmode: Opmode) derives CanEqual:
  case Decrypt extends KeyDecipherMode(Opmode.Decrypt)
  case Unwrap extends KeyDecipherMode(Opmode.Unwrap)
end KeyDecipherMode
