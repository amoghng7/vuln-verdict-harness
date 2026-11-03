package com.example.demo;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

/** Tiny, self-written example for the vuln-verdict demo (MIT). Contains deliberate weaknesses. */
public class AccountService {
    private final Connection conn;

    public AccountService(Connection conn) {
        this.conn = conn;
    }

    // Looks up an account by the user-supplied name.
    public ResultSet findAccount(String name) throws Exception {
        Statement st = conn.createStatement();
        String sql = String.format("SELECT id, balance FROM accounts WHERE owner = '%s'", name);
        return st.executeQuery(sql);
    }

    // Counts rows of a fixed table; nothing user-controlled reaches the query.
    public int countAccounts() throws Exception {
        Statement st = conn.createStatement();
        String table = "accounts";
        ResultSet rs = st.executeQuery(String.format("SELECT COUNT(*) FROM %s", table));
        rs.next();
        return rs.getInt(1);
    }

    // Stores a password hash.
    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes("UTF-8"));
    }

    // Encrypts an account export.
    public byte[] encryptExport(byte[] data, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
        return c.doFinal(data);
    }

    // Parses an XML statement uploaded by the customer.
    public Document parseStatement(java.io.InputStream upload) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(upload);
    }

    // Reads the default settings file shipped inside the application jar.
    public Document loadBundledDefaults() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(AccountService.class.getResourceAsStream("/defaults.xml"));
    }
}
