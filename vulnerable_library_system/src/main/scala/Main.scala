package com.vulnerable.library

import org.apache.spark.sql.SparkSession
import spark.jobserver.api.{SparkJob, SparkJobInvalid, SparkJobValid, SparkJobValidation}
import com.sun.net.httpserver.{HttpServer, HttpHandler, HttpExchange}
import java.net.InetSocketAddress
import scala.io.Source
import routes.{BookRoutes, UserRoutes}

// Vuln 1: CWE-259 - Hardcoded Password
object Main {
  val SECRET_KEY = "hardcoded_secret_123" // Vuln 2: CWE-321 - Hardcoded Cryptographic Key

  def main(args: Array[String]): Unit = {
    // Vuln 3: CWE-16 - Configuration
    System.setProperty("spark.debug.mode", "true") // Debug mode in production

    val spark = SparkSession.builder()
      .appName("VulnerableLibrary")
      .master("local[*]")
      .getOrCreate()

    // Vuln 4: CWE-319 - Cleartext Transmission of Sensitive Information
    val server = HttpServer.create(new InetSocketAddress(8080), 0) // No HTTPS

    server.createContext("/", new HttpHandler {
      override def handle(exchange: HttpExchange): Unit = {
        // Vuln 5: CWE-79 - Cross-Site Scripting (XSS)
        val name = exchange.getRequestURI.getQuery.split("=").last
        val response = s"Welcome $name"
        exchange.sendResponseHeaders(200, response.length)
        exchange.getResponseBody.write(response.getBytes)
        exchange.getResponseBody.close()
      }
    })

    server.createContext("/login", UserRoutes.loginHandler)
    server.createContext("/register", UserRoutes.registerHandler)
    server.createContext("/books", BookRoutes.booksHandler)

    // Vuln 6: CWE-200 - Information Exposure
    server.createContext("/error", new HttpHandler {
      override def handle(exchange: HttpExchange): Unit = {
        val error = new Exception("Test error").getStackTrace.toString // Vuln 7: CWE-209
        exchange.sendResponseHeaders(500, error.length)
        exchange.getResponseBody.write(error.getBytes)
        exchange.getResponseBody.close()
      }
    })

    server.start()
    println("Server running on http://localhost:8080")
  }
}
