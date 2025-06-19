ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "3.7.1"

ThisBuild / organization := "com.peknight"

ThisBuild / publishTo := {
  val nexus = "https://nexus.peknight.com/repository"
  if (isSnapshot.value)
    Some("snapshot" at s"$nexus/maven-snapshots/")
  else
    Some("releases" at s"$nexus/maven-releases/")
}

ThisBuild / credentials ++= Seq(
  Credentials(Path.userHome / ".sbt" / ".credentials")
)

ThisBuild / resolvers ++= Seq(
  "Pek Nexus" at "https://nexus.peknight.com/repository/maven-public/",
)

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
      "com.peknight" %%% "cats-instances-time" % pekInstancesVersion,
      "com.peknight" %%% "commons-text" % pekCommonsVersion,
      "com.peknight" %%% "commons-time" % pekCommonsVersion,
      "com.peknight" %%% "validation-spire" % pekValidationVersion,
      "org.scalatest" %%% "scalatest-flatspec" % scalaTestVersion % Test,
      "org.typelevel" %%% "cats-effect-testing-scalatest" % catsEffectTestingScalaTestVersion % Test,
      "com.peknight" %%% "security-bcprov" % pekSecurityVersion % Test,
    ),
  )
  .jvmSettings(
    libraryDependencies ++= Seq(
      logbackClassic % Test,
    ),
  )

val http4sVersion = "1.0.0-M34"
val scalaTestVersion = "3.2.19"
val catsEffectTestingScalaTestVersion = "1.6.0"
val logbackVersion = "1.5.18"

val pekVersion = "0.1.0-SNAPSHOT"
val pekCommonsVersion = pekVersion
val pekExtVersion = pekVersion
val pekInstancesVersion = pekVersion
val pekValidationVersion = pekVersion
val pekCodecVersion = pekVersion
val pekSecurityVersion = pekVersion
val logbackClassic = "ch.qos.logback" % "logback-classic" % logbackVersion
