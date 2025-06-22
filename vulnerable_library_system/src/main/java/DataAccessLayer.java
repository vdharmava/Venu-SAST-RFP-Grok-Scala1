package com.vulnerable.library;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

// Vuln 10: CWE-89 - SQL Injection
public class DataAccessLayer {
    public static ResultSet executeQuery(Connection conn, String query) throws Exception {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query); // No parameterized queries
    }

    public static void executeUpdate(Connection conn, String query) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeUpdate(query);
    }
}
