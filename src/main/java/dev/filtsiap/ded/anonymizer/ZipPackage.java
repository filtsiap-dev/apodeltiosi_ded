package dev.filtsiap.ded.anonymizer;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import org.apache.commons.compress.archivers.zip.Zip64ExtendedInformationExtraField;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.compress.archivers.zip.ZipExtraField;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;

/**
 * In-memory ZIP access with Python {@code zipfile} semantics: entries in central-directory
 * order, names decoded as CP437 unless the UTF-8 flag is set, and a duplicated name resolving to
 * its last entry (as {@code ZipFile.read(name)} does).
 */
final class ZipPackage {

    /** One central-directory entry and the bytes {@code zipfile.read(entry.name)} returns. */
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

    /** A member whose data could not be read back intact ({@code testzip}'s answer). */
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
     * Opens the archive and reads every member, verifying each CRC like {@code ZipFile.testzip()}.
     *
     * @throws BadZipFile    when the bytes are not a ZIP archive
     * @throws CorruptMember for the first member that fails to read or fails its CRC
     */
    @SuppressWarnings("deprecation") // this constructor exists unchanged in Commons Compress 1.25 through 1.28
    static ZipPackage read(byte[] data) throws BadZipFile, CorruptMember {
        List<ZipArchiveEntry> entries;
        Map<String, byte[]> lastData = new LinkedHashMap<>();
        try (ZipFile zf = new ZipFile(new SeekableInMemoryByteChannel(data), "in-memory DOCX", "Cp437", false)) {
            entries = Collections.list(zf.getEntries());
            Map<String, ZipArchiveEntry> lastEntry = new LinkedHashMap<>();
            for (ZipArchiveEntry e : entries) {
                lastEntry.put(e.getName(), e);
            }
            for (ZipArchiveEntry e : entries) {
                ZipArchiveEntry target = lastEntry.get(e.getName());
                if (lastData.containsKey(e.getName())) {
                    continue;
                }
                lastData.put(e.getName(), readVerified(zf, target));
            }
        } catch (CorruptMember e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw new BadZipFile("Not a valid DOCX package", e);
        }
        List<Member> members = new ArrayList<>();
        for (ZipArchiveEntry e : entries) {
            members.add(new Member(e, lastData.get(e.getName())));
        }
        return new ZipPackage(members);
    }

    private static byte[] readVerified(ZipFile zf, ZipArchiveEntry entry) throws CorruptMember {
        try {
            if (!zf.canReadEntryData(entry)) {
                throw new CorruptMember(entry.getName(), null);
            }
            byte[] bytes;
            try (InputStream in = zf.getInputStream(entry)) {
                bytes = in.readAllBytes();
            }
            CRC32 crc = new CRC32();
            crc.update(bytes);
            if (entry.getCrc() != -1 && crc.getValue() != entry.getCrc()) {
                throw new CorruptMember(entry.getName(), null);
            }
            return bytes;
        } catch (IOException | RuntimeException e) {
            throw new CorruptMember(entry.getName(), e);
        }
    }

    /** Central-directory order, duplicates included ({@code zipfile.infolist()}). */
    List<Member> members() {
        return members;
    }

    /** {@code zipfile.namelist()} as a set-like view. */
    List<String> names() {
        return members.stream().map(Member::name).toList();
    }

    /** {@code {info.filename: zin.read(info.filename)}}: first-seen order, last entry's bytes. */
    Map<String, byte[]> packageData() {
        Map<String, byte[]> out = new LinkedHashMap<>();
        members.forEach(m -> out.putIfAbsent(m.name(), m.data()));
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
