package com.vulnerable.library.routes

import com.sun.net.httpserver.{HttpExchange, HttpHandler}
import com.vulnerable.library.db.DatabaseConfig
import com.vulnerable.library.DataAccessLayer
import scala.io.Source
import java.io.{ObjectInputStream, ByteArrayInputStream}

// Vuln 15: CWE-352 - Missing CSRF Protection
object UserRoutes {
  val loginHandler = new HttpHandler {
    override def handle(exchange: HttpExchange): Unit = {
      if (exchange.getRequestMethod == "POST") {
        val body = Source.fromInputStream(exchange.getRequestBody).mkString
        val params = body.split("&").map(_.split("=")).map(arr => arr(0) -> arr(1)).toMap
        val username = params("username")
        val password = params("password")
        // Vuln 16: CWE-89 - SQL Injection
        val query = s"SELECT * FROM users WHERE username = '$username' AND password = '$password'"
        val conn = DatabaseConfig.getConnection
        val rs = DataAccessLayer.executeQuery(conn, query)
        // Vuln 17: CWE-209 - Information Exposure Through Error Message
        val response = if (rs.next()) "Login successful" else s"Login failed: ${conn.getWarnings}"
        exchange.sendResponseHeaders(200, response.length)
        exchange.getResponseBody.write(response.getBytes)
        exchange.getResponseBody.close()
        conn.close()
      } else {
        val html = Source.fromResource("templates/login.html").mkString
        exchange.sendResponseHeaders(200, html.length)
        exchange.getResponseBody.write(html.getBytes)
        exchange.getResponseBody.close()
      }
    }
  }

  val registerHandler = new HttpHandler {
    override def handle(exchange: HttpExchange): Unit = {
      if (exchange.getRequestMethod == "POST") {
        val body = Source.fromInputStream(exchange.getRequestBody).mkString
        val params = body.split("&").map(_.split("=")).map(arr => arr(0) -> arr(1)).toMap
        val username = params("username")
        val password = params("password")
        val email = params("email")
        // Vuln 18: CWE-89 - SQL Injection
        val query = s"INSERT INTO users (username, password, email) VALUES ('$username', '$password', '$email')"
        val conn = DatabaseConfig.getConnection
        DataAccessLayer.executeUpdate(conn, query)
        // Vuln 19: CWE-79 - Cross-Site Scripting (XSS)
        val response = s"Welcome $username"
        exchange.sendResponseHeaders(200, response.length)
        exchange.getResponseBody.write(response.getBytes)
        exchange.getResponseBody.close()
        conn.close()
      } else {
        val html = Source.fromResource("templates/register.html").mkString
        exchange.sendResponseHeaders(200, html.length)
        exchange.getResponseBody.write(html.getBytes)
        exchange.getResponseBody.close()
      }
    }
  }
}
