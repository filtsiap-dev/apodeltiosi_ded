package dev.filtsiap.ded.anonymizer;

import dev.filtsiap.ded.anonymizer.pycompat.PyFloat;
import dev.filtsiap.ded.anonymizer.pycompat.PyRepr;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import org.apache.commons.compress.archivers.zip.Zip64ExtendedInformationExtraField;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipExtraField;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;

/**
 * In-memory ZIP access, bounded by {@link ResourceLimits} (port of the package half of
 * {@code docx_engine.py}): entries in central-directory order, names decoded as CP437 unless the
 * UTF-8 flag is set.
 *
 * <p>Opening reads the central directory only. {@link #read} then PREFLIGHTS it (member count,
 * duplicate and unsafe names, encryption, compression method, declared sizes and ratio) before a
 * single byte is decompressed, which is the only way to refuse a decompression bomb without first
 * decompressing it. The declared sizes are not trusted afterwards: every read stops one byte past
 * what the member declared, and the CRC check catches a directory that lied the other way.
 */
final class ZipPackage {

    /** One central-directory entry and its bytes. */
    record Member(ZipArchiveEntry info, byte[] data) {
        String name() {
            return info.getName();
        }
    }

    private final List<Member> members;

    private ZipPackage(List<Member> members) {
        this.members = members;
    }

    /** Thrown where Python raises {@code zipfile.BadZipFile} or {@code OSError} opening the archive. */
    static final class BadZipFile extends Exception {
        private static final long serialVersionUID = 1L;

        BadZipFile(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** A member whose data could not be read back intact. */
    static final class CorruptMember extends Exception {
        private static final long serialVersionUID = 1L;
        private final String memberName;

        CorruptMember(String memberName, Throwable cause) {
            super("corrupt member", cause);
            this.memberName = memberName;
        }

        String memberName() {
            return memberName;
        }
    }

    /**
     * Preflights the archive against {@code limits}, then reads every member, capped and CRC-verified.
     *
     * @throws BadZipFile                 when the bytes are not a ZIP archive
     * @throws CorruptMember              for the first member that fails to read or fails its CRC
     * @throws ResourceLimitExceededError for a member count, size, total or ratio over its limit
     * @throws InvalidDocumentError       for a duplicate, unsafe, encrypted or unsupported member
     */
    @SuppressWarnings("deprecation") // this constructor exists unchanged in Commons Compress 1.25 through 1.28
    static ZipPackage read(byte[] data, ResourceLimits limits) throws BadZipFile, CorruptMember {
        ZipFile zf;
        List<ZipArchiveEntry> entries;
        try {
            zf = new ZipFile(new SeekableInMemoryByteChannel(data), "in-memory DOCX", "Cp437", false);
            entries = Collections.list(zf.getEntries());
        } catch (IOException | RuntimeException e) {
            throw new BadZipFile("Not a valid DOCX package", e);
        }
        try (zf) {
            preflight(entries, limits);
            List<Member> members = new ArrayList<>();
            long total = 0;
            for (ZipArchiveEntry entry : entries) {
                byte[] bytes = readMember(zf, entry, limits);
                total += bytes.length;
                if (total > limits.maxZipTotalBytes()) {
                    throw new ResourceLimitExceededError("package expands to more than "
                            + limits.maxZipTotalBytes() + " bytes", "ZIP_TOTAL_TOO_LARGE");
                }
                members.add(new Member(entry, bytes));
            }
            return new ZipPackage(members);
        } catch (IOException e) {
            throw new BadZipFile("Not a valid DOCX package", e);
        }
    }

    /** Refuses anything out of bounds using metadata only. Decompresses nothing. */
    private static void preflight(List<ZipArchiveEntry> entries, ResourceLimits limits) {
        if (entries.size() > limits.maxZipMembers()) {
            throw new ResourceLimitExceededError("package has " + entries.size() + " members; the limit is "
                    + limits.maxZipMembers(), "ZIP_MEMBER_COUNT_EXCEEDED");
        }
        Set<String> seen = new HashSet<>();
        long total = 0;
        long xml = 0;
        for (ZipArchiveEntry entry : entries) {
            String name = entry.getName();
            if (!seen.add(name)) {
                throw new InvalidDocumentError("package contains " + PyRepr.repr(name) + " more than once",
                        "DUPLICATE_MEMBER_NAME");
            }
            String normalised = name.replace('\\', '/');
            if (normalised.startsWith("/") || List.of(normalised.split("/", -1)).contains("..")) {
                throw new InvalidDocumentError("package contains a member name that escapes the package",
                        "UNSAFE_MEMBER_NAME");
            }
            if (entry.getGeneralPurposeBit().usesEncryption()) {
                throw new InvalidDocumentError("package member " + PyRepr.repr(name) + " is encrypted",
                        "ENCRYPTED_ZIP_MEMBER");
            }
            if (entry.getMethod() != ZipEntry.STORED && entry.getMethod() != ZipEntry.DEFLATED) {
                throw new InvalidDocumentError("package member " + PyRepr.repr(name)
                        + " uses unsupported compression method " + entry.getMethod(), "UNSUPPORTED_COMPRESSION_METHOD");
            }
            long size = entry.getSize();
            if (size < 0) {
                // The central directory always states it; an unknown size cannot be bounded.
                throw new InvalidDocumentError("package member " + PyRepr.repr(name) + " declares no size",
                        "CORRUPT_ZIP_MEMBER");
            }
            if (size > limits.maxZipMemberBytes()) {
                throw new ResourceLimitExceededError("package member expands to " + size + " bytes; the limit is "
                        + limits.maxZipMemberBytes(), "ZIP_MEMBER_TOO_LARGE");
            }
            total += size;
            if (total > limits.maxZipTotalBytes()) {
                throw new ResourceLimitExceededError("package expands to more than " + limits.maxZipTotalBytes()
                        + " bytes", "ZIP_TOTAL_TOO_LARGE");
            }
            if (isXmlPart(name)) {
                // Every XML part becomes a DOM, many times its size in heap: this is the memory bound.
                xml += size;
                if (xml > limits.maxXmlBytes()) {
                    throw new ResourceLimitExceededError("package XML parts expand to more than "
                            + limits.maxXmlBytes() + " bytes", "XML_TOTAL_TOO_LARGE");
                }
            }
            if (size > limits.compressionRatioFloorBytes()) {
                // Only large members are judged on ratio: small XML parts reach 30:1 legitimately.
                double ratio = (double) size / Math.max(entry.getCompressedSize(), 1);
                if (ratio > limits.maxCompressionRatio()) {
                    throw new ResourceLimitExceededError("package member expands " + PyFloat.fixed(ratio, 0)
                            + ":1; the limit is " + PyFloat.fixed(limits.maxCompressionRatio(), 0) + ":1",
                            "ZIP_COMPRESSION_RATIO_EXCEEDED");
                }
            }
        }
    }

    /** The members every stage parses into a DOM ({@code DocxEngine.parseXmlParts}). */
    static boolean isXmlPart(String name) {
        return name.endsWith(".xml") || name.endsWith(".rels");
    }

    /** What the central directory declares: the XML parts and the whole package, expanded. */
    record DeclaredSizes(long xmlBytes, long totalBytes) {
    }

    /**
     * The declared expanded sizes, read from the central directory alone (nothing decompressed),
     * for the memory estimate made before any parsing. Declared sizes are binding: {@link #read}
     * refuses a member that expands past what it declared. Null when the bytes are not a ZIP
     * archive or declare a size they cannot bound; validation then refuses them.
     */
    @SuppressWarnings("deprecation") // as in read()
    static DeclaredSizes declaredSizes(byte[] data) {
        long xml = 0;
        long total = 0;
        try (ZipFile zf = new ZipFile(new SeekableInMemoryByteChannel(data), "in-memory DOCX", "Cp437", false)) {
            for (ZipArchiveEntry entry : Collections.list(zf.getEntries())) {
                long size = entry.getSize();
                if (size < 0) {
                    return null;
                }
                total += size;
                if (isXmlPart(entry.getName())) {
                    xml += size;
                }
            }
        } catch (IOException | RuntimeException e) {
            return null;
        }
        return new DeclaredSizes(xml, total);
    }

    /** Reads one member, never more than one byte past what it declared, and verifies its CRC. */
    private static byte[] readMember(ZipFile zf, ZipArchiveEntry entry, ResourceLimits limits) throws CorruptMember {
        long cap = Math.min(entry.getSize(), limits.maxZipMemberBytes());
        byte[] bytes;
        try (InputStream in = zf.getInputStream(entry)) {
            bytes = in.readNBytes((int) Math.min(cap + 1, Integer.MAX_VALUE - 8));
        } catch (IOException | RuntimeException e) {
            throw new CorruptMember(entry.getName(), e);
        }
        if (bytes.length > cap) {
            throw new ResourceLimitExceededError("package member " + PyRepr.repr(entry.getName())
                    + " is larger than it declared", "ZIP_MEMBER_TOO_LARGE");
        }
        CRC32 crc = new CRC32();
        crc.update(bytes);
        if (entry.getCrc() != -1 && crc.getValue() != entry.getCrc()) {
            throw new CorruptMember(entry.getName(), null);
        }
        return bytes;
    }

    /** Central-directory order ({@code zipfile.infolist()}); names are unique. */
    List<Member> members() {
        return members;
    }

    /** {@code zipfile.namelist()}. */
    List<String> names() {
        return members.stream().map(Member::name).toList();
    }

    /** {@code {info.filename: data}} in central-directory order. */
    Map<String, byte[]> packageData() {
        Map<String, byte[]> out = new LinkedHashMap<>();
        members.forEach(m -> out.put(m.name(), m.data()));
        return out;
    }

    /** Entry that copies metadata from a source entry, platform included. */
    private static final class CopiedEntry extends ZipArchiveEntry {
        CopiedEntry(ZipArchiveEntry source) {
            super(source.getName());
            int method = source.getMethod();
            setMethod(method == ZipEntry.STORED ? ZipEntry.STORED : ZipEntry.DEFLATED);
            setTime(source.getTime());
            setComment(source.getComment());
            setInternalAttributes(source.getInternalAttributes());
            setExternalAttributes(source.getExternalAttributes());
            setPlatform(source.getPlatform());
            List<ZipExtraField> extras = new ArrayList<>();
            for (ZipExtraField f : source.getExtraFields(true)) {
                if (!(f instanceof Zip64ExtendedInformationExtraField)) {
                    extras.add(f);
                }
            }
            setExtraFields(extras.toArray(new ZipExtraField[0]));
        }
    }

    /** Writes members, copying each source entry's metadata ({@code docx_engine._copy_zipinfo}). */
    static byte[] write(List<Map.Entry<ZipArchiveEntry, byte[]>> items) throws IOException {
        SeekableInMemoryByteChannel channel = new SeekableInMemoryByteChannel();
        try (ZipArchiveOutputStream out = new ZipArchiveOutputStream(channel)) {
            out.setEncoding("UTF-8");
            for (Map.Entry<ZipArchiveEntry, byte[]> item : items) {
                out.putArchiveEntry(new CopiedEntry(item.getKey()));
                out.write(item.getValue());
                out.closeArchiveEntry();
            }
            out.finish();
        }
        byte[] all = channel.array();
        return java.util.Arrays.copyOf(all, (int) channel.size());
    }
}
