ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "3.5.0"

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
      "com.peknight" %%% "cats-parse-ext" % pekExtVersion,
      "com.peknight" %%% "cats-instances-scodec-bits" % pekInstancesVersion,
      "com.peknight" %%% "commons-string" % pekCommonsVersion,
      "com.peknight" %%% "validation-spire" % pekValidationVersion,
      "org.typelevel" %%% "cats-effect-testing-scalatest" % catsEffectTestingScalaTestVersion % Test,
      "com.peknight" %%% "security-bcprov" % pekSecurityVersion % Test,
    ),
  )
  .jvmSettings(
    libraryDependencies ++= Seq(
      jwtCirce % Test,
      scalaJwk % Test,
      jose4j % Test,
      logbackClassic % Test,
    ),
  )

val http4sVersion = "1.0.0-M34"
val pekVersion = "0.1.0-SNAPSHOT"
val pekSecurityVersion = pekVersion
val pekCodecVersion = pekVersion
val pekExtVersion = pekVersion
val pekInstancesVersion = pekVersion
val pekCommonsVersion = pekVersion
val pekValidationVersion = pekVersion
val catsEffectTestingScalaTestVersion = "1.5.0"

val jwtCirceVersion = "10.0.1"
val scalaJwkVersion = "1.2.24"
val jose4jVersion = "0.9.6"
val logbackVersion = "1.5.8"
val jwtCirce = "com.github.jwt-scala" %% "jwt-circe" % jwtCirceVersion
val scalaJwk = "com.chatwork" %% "scala-jwk" % scalaJwkVersion
val jose4j = "org.bitbucket.b_c" % "jose4j" % jose4jVersion
val logbackClassic = "ch.qos.logback" % "logback-classic" % logbackVersion
