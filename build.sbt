ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "3.4.2"

ThisBuild / organization := "com.peknight"

lazy val commonSettings = Seq(
  scalacOptions ++= Seq(
    "-feature",
    "-deprecation",
    "-unchecked",
    "-Xfatal-warnings",
    "-language:strictEquality",
    "-Xmax-inlines:64"
  ),
)

lazy val jose = (project in file("."))
  .aggregate(
    joseCore.jvm,
    joseCore.js,
  )
  .settings(commonSettings)
  .settings(
    name := "jose",
  )

lazy val joseCore = (crossProject(JSPlatform, JVMPlatform) in file("jose-core"))
  .settings(commonSettings)
  .settings(
    name := "jose-core",
    libraryDependencies ++= Seq(
      "com.peknight" %%% "security-core" % pekSecurityVersion,
      "com.peknight" %%% "codec-circe-parser" % pekCodecVersion,
      "com.peknight" %%% "codec-base" % pekCodecVersion,
      "com.peknight" %%% "codec-http4s" % pekCodecVersion,
      "com.peknight" %%% "io-core" % pekIoVersion,
      "com.peknight" %%% "commons-string" % pekCommonsVersion,
    ),
  )
  .jvmSettings(
    libraryDependencies ++= Seq(
      "org.typelevel" %%% "cats-effect-testing-scalatest" % catsEffectTestingScalaTestVersion % Test,
      "com.peknight" %%% "security-bcprov" % pekSecurityVersion % Test,
      jwtCirce % Test,
      scalaJwk % Test,
      jose4j % Test,
    ),
  )

val http4sVersion = "1.0.0-M34"
val pekVersion = "0.1.0-SNAPSHOT"
val catsEffectTestingScalaTestVersion = "1.5.0"
val pekSecurityVersion = pekVersion
val pekCodecVersion = pekVersion
val pekIoVersion = pekVersion
val pekCommonsVersion = pekVersion
val pekExtVersion = pekVersion

val jwtCirceVersion = "10.0.1"
val scalaJwkVersion = "1.2.24"
val jose4jVersion = "0.9.6"
val jwtCirce = "com.github.jwt-scala" %% "jwt-circe" % jwtCirceVersion
val scalaJwk = "com.chatwork" %% "scala-jwk" % scalaJwkVersion
val jose4j = "org.bitbucket.b_c" % "jose4j" % jose4jVersion