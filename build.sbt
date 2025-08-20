import com.peknight.build.gav.*
import com.peknight.build.sbt.*

commonSettings

lazy val jose = (project in file("."))
  .settings(name := "jose")
  .aggregate(
    joseCore.jvm,
    joseCore.js,
  )

lazy val joseCore = (crossProject(JVMPlatform, JSPlatform) in file("jose-core"))
  .settings(name := "jose-core")
  .settings(crossDependencies(
    peknight.security,
    peknight.codec.circe.parser,
    peknight.codec.base,
    peknight.codec.http4s,
    peknight.ext.catsParse,
    peknight.instances.cats.scodec.bits,
    peknight.instances.cats.time,
    peknight.commons.text,
    peknight.commons.time,
    peknight.validation.spire,
  ))
  .settings(crossTestDependencies(
    scalaTest.flatSpec,
    typelevel.catsEffect.testingScalaTest,
    peknight.security.bouncyCastle.provider,
  ))
  .jvmSettings(libraryDependencies ++= Seq(jvmTestDependency(logback.classic)))
