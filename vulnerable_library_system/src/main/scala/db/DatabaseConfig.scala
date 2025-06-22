package com.vulnerable.library.db

import java.sql.{Connection, DriverManager}

// Vuln 8: CWE-257 - Storing Passwords in Plaintext
object DatabaseConfig {
  val DB_URL = "jdbc:sqlite:library.db"
  val DB_USER = "admin"
  val DB_PASS = "admin123"

  def getConnection: Connection = {
    // Vuln 9: CWE-321 - Hardcoded Cryptographic Key
    DriverManager.getConnection(DB_URL, DB_USER, DB_PASS)
  }
}