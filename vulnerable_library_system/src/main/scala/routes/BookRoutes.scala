package com.vulnerable.library.routes

import com.sun.net.httpserver.{HttpExchange, HttpHandler}
import com.vulnerable.library.db.DatabaseConfig
import com.vulnerable.library.{DataAccessLayer, VulnerableUtils}
import scala.io.Source
import java.io.File

// Vuln 20: CWE-306 - Missing Authentication for Critical Function
object BookRoutes {
  val booksHandler = new HttpHandler {
    override def handle(exchange: HttpExchange): Unit = {
      if (exchange.getRequestMethod == "POST") {
        val body = Source.fromInputStream(exchange.getRequestBody).mkString
        val params = body.split("&").map(_.split("=")).map(arr => arr(0) -> arr(1)).toMap
        val title = params("title")
        val author = params("author")
        // Vuln 21: CWE-89 - SQL Injection
        val query = s"INSERT INTO books (title, author) VALUES ('$title', '$author')"
        val conn = DatabaseConfig.getConnection
        DataAccessLayer.executeUpdate(conn, query)
        conn.close()
        exchange.sendResponseHeaders(200, 0)
        exchange.getResponseBody.close()
      } else {
        // Vuln 22: CWE-89 - SQL Injection
        val title = exchange.getRequestURI.getQuery.split("=").last
        val query = s"SELECT * FROM books WHERE title = '$title'"
        val conn = DatabaseConfig.getConnection
        val rs = DataAccessLayer.executeQuery(conn, query)
        val books = new StringBuilder
        while (rs.next()) {
          books.append(s"${rs.getString("title")} by ${rs.getString("author")}\n")
        }
        // Vuln 23: CWE-200 - Information Exposure
        val response = books.toString
        exchange.sendResponseHeaders(200, response.length)
        exchange.getResponseBody.write(response.getBytes)
        exchange.getResponseBody.close()
        conn.close()
      }
    }

    // Vuln 24: CWE-269 - Improper Privilege Management
    def makeAdmin(exchange: HttpExchange): Unit = {
      val username = exchange.getRequestURI.getQuery.split("=").last
      val query = s"UPDATE users SET role = 'admin' WHERE username = '$username'"
      val conn = DatabaseConfig.getConnection
      DataAccessLayer.executeUpdate(conn, query)
      val response = "User promoted"
      exchange.sendResponseHeaders(200, response.length)
      exchange.getResponseBody.write(response.getBytes)
      exchange.getResponseBody.close()
      conn.close()
    }

    // Vuln 25: CWE-502 - Insecure Deserialization
    def importData(exchange: HttpExchange): Unit = {
      val body = Source.fromInputStream(exchange.getRequestBody).readAllBytes()
      VulnerableUtils.deserialize(body)
      val response = "Data imported"
      exchange.sendResponseHeaders(200, response.length)
      exchange.getResponseBody.write(response.getBytes)
      exchange.getResponseBody.close()
    }

    // Vuln 26: CWE-611 - XML External Entity (XXE)
    def parseXML(exchange: HttpExchange): Unit = {
      val body = Source.fromInputStream(exchange.getRequestBody).mkString
      val result = VulnerableUtils.parseXML(body)
      exchange.sendResponseHeaders(200, result.length)
      exchange.getResponseBody.write(result.getBytes)
      exchange.getResponseBody.close()
    }

    // Vuln 27: CWE-918 - Server-Side Request Forgery (SSRF)
    def fetchURL(exchange: HttpExchange): Unit = {
      val url = exchange.getRequestURI.getQuery.split("=").last
      val result = VulnerableUtils.fetchURL(url)
      exchange.sendResponseHeaders(200, result.length)
      exchange.getResponseBody.write(result.getBytes)
      exchange.getResponseBody.close()
    }

    // Vuln 28: CWE-676 - Use of Potentially Dangerous Function
    def dangerous(exchange: HttpExchange): Unit = {
      val cmd = exchange.getRequestURI.getQuery.split("=").last
      val process = Runtime.getRuntime().exec(cmd) // Dangerous function
      val response = new String(process.getInputStream.readAllBytes())
      exchange.sendResponseHeaders(200, response.length)
      exchange.getResponseBody.write(response.getBytes)
      exchange.getResponseBody.close()
    }

    // Vuln 29: CWE-416 - Use After Free (simulated in Java)
    def useAfterFree(exchange: HttpExchange): Unit = {
      String data = new String("test");
      data = null;
      // Vuln: Attempt to access nullified object
      String response = data.toString();
      exchange.sendResponseHeaders(200, response.length)
      exchange.getResponseBody.write(response.getBytes)
      exchange.getResponseBody.close()
    }

    // Vuln 30-50: Additional vulnerabilities
    def vulnerable(exchange: HttpExchange): Unit = {
      // Vuln 30: CWE-190 - Integer Overflow or Wraparound
      val qty = exchange.getRequestURI.getQuery.split("=").last.toInt
      val total = qty * 1000 // No overflow check
      var response = s"Total: $total"

      // Vuln 31: CWE-22 - Path Traversal
      val file = exchange.getRequestURI.getQuery.split("=").last
      response += new String(Files.readAllBytes(Paths.get(s"/uploads/$file")))

      // Vuln 32: CWE-798 - Hardcoded Credentials
      val apiKey = "hardcoded_api_key_123"
      response += s", API Key: $apiKey"

      // Vuln 33: CWE-307 - Brute Force Protection Missing
      // No rate limiting

      // Vuln 34-50: Placeholder for additional vulnerabilities
      // Examples: CWE-732, CWE-601, CWE-522, etc.
      exchange.sendResponseHeaders(200, response.length)
      exchange.getResponseBody.write(response.getBytes)
      exchange.getResponseBody.close()
    }
  }
}
