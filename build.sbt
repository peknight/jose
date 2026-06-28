import com.peknight.build.gav.*
import com.peknight.build.sbt.*

commonSettings

lazy val jose = (project in file("."))
  .settings(name := "jose")
  .aggregate(joseCore.projectRefs *)

lazy val joseCore = (projectMatrix in file("jose-core"))
  .settings(name := "jose-core")
  .settings(libraryDependencies ++= dependencies(
    peknight.security,
    peknight.codec.circe.parser,
    peknight.codec.base,
    peknight.codec.http4s,
    peknight.cats,
    peknight.cats.scodec.bits,
    peknight.catsParse,
    peknight.commons.time,
    peknight.validation.spire,
  ))
  .settings(libraryDependencies ++= testDependencies(
    scalaTest.flatSpec,
    typelevel.catsEffect.testingScalaTest,
    peknight.security.bouncyCastle.provider,
  ))
  .jvmPlatform(
    scalaVersions = Seq(scala.scala3.version),
    settings = Seq(
      libraryDependencies ++= jvmTestDependencies(logback.classic)
    )
  )
  .jsPlatform(scalaVersions = Seq(scala.scala3.version))
