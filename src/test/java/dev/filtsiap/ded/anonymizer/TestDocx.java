package dev.filtsiap.ded.anonymizer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/** Builds small synthetic DOCX packages. All content is invented. */
public final class TestDocx {

    public static final String W = "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"";

    private final Map<String, byte[]> parts = new LinkedHashMap<>();

    public static final String MAIN_CONTENT_TYPE =
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
    public static final String OFFICE_DOCUMENT_REL =
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";

    private TestDocx() {
        put("[Content_Types].xml", contentTypes(MAIN_CONTENT_TYPE));
        put("_rels/.rels", "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
                + "<Relationship Id=\"rId1\" Type=\"" + OFFICE_DOCUMENT_REL + "\" Target=\"word/document.xml\"/>"
                + "</Relationships>");
    }

    /** A {@code [Content_Types].xml} declaring {@code mainType} for the main document part. */
    public static String contentTypes(String mainType) {
        return "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
                + "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
                + "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
                + "<Override PartName=\"/word/document.xml\" ContentType=\"" + mainType + "\"/></Types>";
    }

    /** A package whose body holds one paragraph per argument (one run each). */
    public static TestDocx paragraphs(String... paragraphs) {
        StringBuilder body = new StringBuilder();
        for (String p : paragraphs) {
            body.append(p(p));
        }
        return new TestDocx().document(body.toString());
    }

    public static String p(String text) {
        return "<w:p><w:r><w:t xml:space=\"preserve\">" + esc(text) + "</w:t></w:r></w:p>";
    }

    public static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    public TestDocx document(String bodyXml) {
        return put("word/document.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<w:document " + W + "><w:body>"
                + bodyXml + "</w:body></w:document>");
    }

    public TestDocx put(String name, String xml) {
        parts.put(name, xml.getBytes(StandardCharsets.UTF_8));
        return this;
    }

    public TestDocx remove(String name) {
        parts.remove(name);
        return this;
    }

    public byte[] bytes() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(buf)) {
            for (Map.Entry<String, byte[]> e : parts.entrySet()) {
                zip.putNextEntry(new ZipEntry(e.getKey()));
                zip.write(e.getValue());
                zip.closeEntry();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return buf.toByteArray();
    }

    /** Reads one part of a package as UTF-8, or null. */
    public static String part(byte[] docx, String name) {
        try (ZipInputStream zip = new ZipInputStream(new java.io.ByteArrayInputStream(docx))) {
            for (ZipEntry e; (e = zip.getNextEntry()) != null; ) {
                if (e.getName().equals(name)) {
                    return new String(zip.readAllBytes(), StandardCharsets.UTF_8);
                }
            }
            return null;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** A synthetic AFM with a valid checksum, built from eight digits. */
    public static String validAfm(String eightDigits) {
        int total = 0;
        for (int i = 0; i < 8; i++) {
            total += (eightDigits.charAt(i) - '0') << (8 - i);
        }
        return eightDigits + (total % 11) % 10;
    }

    /** A synthetic Greek IBAN with valid mod-97 check digits, built from its 23-digit BBAN. */
    public static String validGreekIban(String twentyThreeDigits) {
        // "GR00" moved to the end, letters as numbers (G=16, R=27): 98 minus the remainder.
        int check = 98 - new java.math.BigInteger(twentyThreeDigits + "162700").mod(java.math.BigInteger.valueOf(97))
                .intValue();
        return "GR" + (check < 10 ? "0" : "") + check + twentyThreeDigits;
    }
}
