package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * The package preflight and the capped member read. Every archive is a few kilobytes of invented
 * bytes; the large cases are large only in what their central directory CLAIMS.
 */
class ZipPackageTest {

    /** Tight enough that each bound is crossed with a few kilobytes. */
    static final ResourceLimits TIGHT = new ResourceLimits(20_000_000L, 4, 1_000, 2_500, 50.0, 1_000, 400_000L, 150L, 2_500, 0L);
    /** Room for size, so only the ratio can refuse. */
    static final ResourceLimits RATIO = new ResourceLimits(20_000_000L, 4, 100_000, 200_000, 50.0, 1_000, 400_000L, 150L, 200_000, 0L);

    static byte[] noise(int size) {
        byte[] b = new byte[size];
        new Random(size).nextBytes(b); // incompressible, so the ratio stays near 1:1
        return b;
    }

    static byte[] text(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    static Map<String, byte[]> members(int... sizes) {
        Map<String, byte[]> m = new LinkedHashMap<>();
        for (int i = 0; i < sizes.length; i++) {
            m.put("word/m" + i + ".bin", noise(sizes[i]));
        }
        return m;
    }

    static byte[] zip(Map<String, byte[]> members) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (ZipOutputStream out = new ZipOutputStream(buf)) {
            for (Map.Entry<String, byte[]> e : members.entrySet()) {
                out.putNextEntry(new ZipEntry(e.getKey()));
                out.write(e.getValue());
                out.closeEntry();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return buf.toByteArray();
    }

    static byte[] stored(String name, byte[] data) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (ZipOutputStream out = new ZipOutputStream(buf)) {
            ZipEntry entry = new ZipEntry(name);
            CRC32 crc = new CRC32();
            crc.update(data);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(data.length);
            entry.setCrc(crc.getValue());
            out.putNextEntry(entry);
            out.write(data);
            out.closeEntry();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return buf.toByteArray();
    }

    static byte[] one(String name, String content) {
        return zip(Map.of(name, text(content)));
    }

    // ------------------------------------------------------------------ header patching

    static List<Integer> headers(byte[] zip, int third, int fourth) {
        List<Integer> at = new ArrayList<>();
        for (int i = 0; i + 3 < zip.length; i++) {
            if (zip[i] == 'P' && zip[i + 1] == 'K' && zip[i + 2] == third && zip[i + 3] == fourth) {
                at.add(i);
            }
        }
        return at;
    }

    static int central(byte[] zip) {
        return headers(zip, 1, 2).get(0);
    }

    static int local(byte[] zip) {
        return headers(zip, 3, 4).get(0);
    }

    static void putShort(byte[] b, int at, int v) {
        b[at] = (byte) v;
        b[at + 1] = (byte) (v >>> 8);
    }

    static void putInt(byte[] b, int at, long v) {
        for (int i = 0; i < 4; i++) {
            b[at + i] = (byte) (v >>> (8 * i));
        }
    }

    static void replaceAll(byte[] b, String from, String to) {
        byte[] f = text(from);
        byte[] t = text(to);
        for (int i = 0; i + f.length <= b.length; i++) {
            if (Arrays.equals(b, i, i + f.length, f, 0, f.length)) {
                System.arraycopy(t, 0, b, i, t.length);
            }
        }
    }

    // ------------------------------------------------------------------ assertions

    static ZipPackage read(byte[] zip, ResourceLimits limits) {
        try {
            return ZipPackage.read(zip, limits);
        } catch (ZipPackage.BadZipFile | ZipPackage.CorruptMember e) {
            throw new AssertionError(e);
        }
    }

    static Executable reading(byte[] zip, ResourceLimits limits) {
        return () -> ZipPackage.read(zip, limits);
    }

    static void overLimit(String code, String message, byte[] zip, ResourceLimits limits) {
        ResourceLimitExceededError e = assertThrows(ResourceLimitExceededError.class, reading(zip, limits));
        assertEquals(code, e.code());
        assertEquals(message, e.getMessage());
    }

    static void invalid(String code, String message, byte[] zip) {
        InvalidDocumentError e = assertThrows(InvalidDocumentError.class, reading(zip, ResourceLimits.DEFAULTS));
        assertEquals(code, e.code());
        assertEquals(message, e.getMessage());
    }

    // ------------------------------------------------------------------ resource limits

    @Test
    void memberCountIsBoundedAtTheLimit() {
        assertEquals(4, read(zip(members(10, 10, 10, 10)), TIGHT).members().size());
        overLimit("ZIP_MEMBER_COUNT_EXCEEDED", "package has 5 members; the limit is 4",
                zip(members(10, 10, 10, 10, 10)), TIGHT);
    }

    @Test
    void declaredMemberSizeIsBoundedAtTheLimit() {
        assertEquals(1_000, read(zip(members(1_000)), TIGHT).members().get(0).data().length);
        overLimit("ZIP_MEMBER_TOO_LARGE", "package member expands to 1001 bytes; the limit is 1000",
                zip(members(1_001)), TIGHT);
    }

    @Test
    void expandedTotalIsBoundedAtTheLimit() {
        assertEquals(3, read(zip(members(900, 900, 700)), TIGHT).members().size());
        overLimit("ZIP_TOTAL_TOO_LARGE", "package expands to more than 2500 bytes", zip(members(900, 900, 701)), TIGHT);
    }

    @Test
    void onlyMembersAboveTheFloorAreJudgedOnRatio() {
        read(zip(Map.of("word/small.xml", new byte[1_000])), RATIO); // 1000 zeros: huge ratio, but at the floor
        read(zip(Map.of("word/noise.bin", noise(20_000))), RATIO);   // large, but honest
        ResourceLimitExceededError e = assertThrows(ResourceLimitExceededError.class,
                reading(zip(Map.of("word/bomb.xml", new byte[20_000])), RATIO));
        assertEquals("ZIP_COMPRESSION_RATIO_EXCEEDED", e.code());
        assertTrue(e.getMessage().matches("package member expands \\d+:1; the limit is 50:1"), e.getMessage());
    }

    @Test
    void aDeclaredBombIsRefusedFromTheDirectoryAlone() {
        byte[] z = one("word/document.xml", "<w:document/>");
        // The member claims 2 GiB. Were anything decompressed first, the read would fail on size
        // or CRC; refusing with the declared figure shows nothing was.
        putInt(z, central(z) + 24, 0x7FFF_FFFFL);
        overLimit("ZIP_MEMBER_TOO_LARGE", "package member expands to 2147483647 bytes; the limit is 25000000", z,
                ResourceLimits.DEFAULTS);
    }

    @Test
    void aMemberLargerThanItDeclaredIsCutOffOneBytePastItsClaim() {
        byte[] z = zip(Map.of("word/document.xml", new byte[5_000]));
        putInt(z, central(z) + 24, 100); // the real data inflates to 5000
        overLimit("ZIP_MEMBER_TOO_LARGE", "package member 'word/document.xml' is larger than it declared", z,
                ResourceLimits.DEFAULTS);
    }

    @Test
    void aCrcMismatchIsACorruptMember() {
        byte[] z = one("word/document.xml", "<w:document/>");
        putInt(z, central(z) + 16, 0x1234_5678L);
        ZipPackage.CorruptMember e = assertThrows(ZipPackage.CorruptMember.class, reading(z, ResourceLimits.DEFAULTS));
        assertEquals("word/document.xml", e.memberName());
    }

    // ------------------------------------------------------------------ unsafe packages

    @Test
    void duplicateNamesAreRefusedNotResolved() {
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("word/a.xml", text("<one/>"));
        m.put("word/b.xml", text("<two/>"));
        byte[] z = zip(m);
        replaceAll(z, "word/b.xml", "word/a.xml"); // local and central headers alike
        invalid("DUPLICATE_MEMBER_NAME", "package contains 'word/a.xml' more than once", z);
    }

    @Test
    void namesThatEscapeThePackageAreRefused() {
        for (String name : List.of("../evil.xml", "/evil.xml", "word/../../evil.xml", "word\\..\\evil.xml")) {
            invalid("UNSAFE_MEMBER_NAME", "package contains a member name that escapes the package",
                    one(name, "<x/>"));
        }
        read(one("word/a..b.xml", "<x/>"), ResourceLimits.DEFAULTS); // ".." inside a name is not a segment
    }

    @Test
    void encryptedMembersAreRefused() {
        byte[] z = one("word/document.xml", "<w:document/>");
        putShort(z, central(z) + 8, z[central(z) + 8] | 1);
        putShort(z, local(z) + 6, z[local(z) + 6] | 1);
        invalid("ENCRYPTED_ZIP_MEMBER", "package member 'word/document.xml' is encrypted", z);
    }

    @Test
    void onlyStoredAndDeflatedAreSupported() {
        read(stored("word/document.xml", text("<w:document/>")), ResourceLimits.DEFAULTS);
        byte[] z = one("word/document.xml", "<w:document/>");
        putShort(z, central(z) + 10, 12); // bzip2
        putShort(z, local(z) + 8, 12);
        invalid("UNSUPPORTED_COMPRESSION_METHOD",
                "package member 'word/document.xml' uses unsupported compression method 12", z);
    }
}
