name := "vulnerable-library-system"

version := "1.0"

scalaVersion := "2.13.10"

libraryDependencies ++= Seq(
  "org.apache.spark" %% "spark-sql" % "3.3.0",
  "com.typesafe.play" %% "play-json" % "2.9.3",
  "org.xerial" % "sqlite-jdbc" % "3.36.0.3"
)
