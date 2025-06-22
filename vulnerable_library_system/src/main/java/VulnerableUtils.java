package com.vulnerable.library;

import java.io.*;
import java.security.MessageDigest;
import javax.xml.parsers.DocumentBuilderFactory;
import java.net.URL;

// Vuln 11: CWE-502 - Insecure Deserialization
public class VulnerableUtils {
    public static Object deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject(); // Unsafe deserialization
    }

    // Vuln 12: CWE-611 - XML External Entity (XXE)
    public static String parseXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes())).getDocumentElement().getTagName();
    }

    // Vuln 13: CWE-918 - Server-Side Request Forgery (SSRF)
    public static String fetchURL(String url) throws Exception {
        return new String(new URL(url).openStream().readAllBytes()); // No validation
    }

    // Vuln 14: CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
    public static String hash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // Broken algorithm
        byte[] hash = md.digest(input.getBytes());
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) hex.append(String.format("%02x", b));
        return hex.toString();
    }
}
