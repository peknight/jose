ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "3.3.1"

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
    ),
  )

