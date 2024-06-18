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
      "com.peknight" %%% "codec-base" % pekCodecVersion,
      "com.peknight" %%% "codec-http4s" % pekCodecVersion,
      "com.peknight" %%% "commons-string" % pekCommonsVersion,
      "org.http4s" %%% "http4s-core" % http4sVersion,
    ),
  )
  .jvmSettings(
    libraryDependencies ++= Seq(
      "com.github.jwt-scala" %% "jwt-circe" % "10.0.1" % Test,
      "com.chatwork" %% "scala-jwk" % "1.2.24" % Test,
      "org.bitbucket.b_c" % "jose4j" % "0.9.6" % Test,
    ),
  )

val http4sVersion = "1.0.0-M34"
val pekVersion = "0.1.0-SNAPSHOT"
val pekSecurityVersion = pekVersion
val pekCodecVersion = pekVersion
val pekCommonsVersion = pekVersion
