package dev.filtsiap.ded.anonymizer;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Memory-based admission (Java-only): before a document is parsed, it reserves the heap it may
 * need from one process-wide budget, and waits while the documents in progress hold it.
 *
 * <p>Why: the parsing is where the heap goes, and how much is not a function of the upload. A
 * DOCX is a ZIP of XML, every XML part becomes a DOM, and the package is parsed several times,
 * with some of those trees alive together. Measured on element-dense XML, a document needs about
 * {@value #HEAP_PER_XML_BYTE} bytes of heap per byte of XML: 5 MB of XML, under 70 KB uploaded,
 * needed 508 MB. Counting requests ({@code ANON_MAX_CONCURRENT_REQUESTS}) cannot bound that; a
 * few such documents at once ran the JVM out of memory, failing every document in it.
 *
 * <p>The estimate comes from the sizes the central directory declares, read before anything is
 * decompressed, and declared sizes are binding ({@link ZipPackage#read} refuses a member that
 * expands past its declaration). It is deliberately the worst case: a real decision needs far
 * less, and the price of overestimating is waiting, not failing. A document whose estimate alone
 * exceeds the whole budget is refused (413) rather than left waiting for room that never comes.
 */
public final class MemoryGate {

    private static final Logger LOG = LoggerFactory.getLogger("anonymizer.pipeline");

    /** Heap per byte of XML part, worst case measured (element-dense parts, all parsed). */
    static final long HEAP_PER_XML_BYTE = 100;
    /** Heap per byte of the whole expanded package: its byte copies, held by several stages. */
    static final long HEAP_PER_PACKAGE_BYTE = 4;
    /** Per document: the upload, the result, and the stages' fixed structures. */
    static final long BASE_BYTES = 16L * 1024 * 1024;
    /** {@code ANON_MEMORY_BUDGET_BYTES=0}: this share of the maximum heap. */
    static final double AUTO_BUDGET_SHARE = 0.6;

    /** One semaphore per budget (in KiB permits); a process runs with one. */
    private static final Map<Long, Semaphore> GATES = new ConcurrentHashMap<>();

    private MemoryGate() {
    }

    /** A reservation; closing it returns the heap to the budget. */
    public static final class Permit implements AutoCloseable {
        private final Semaphore gate;
        private final int kib;
        private boolean closed;

        private Permit(Semaphore gate, int kib) {
            this.gate = gate;
            this.kib = kib;
        }

        @Override
        public void close() {
            if (!closed) {
                closed = true;
                gate.release(kib);
            }
        }
    }

    /** The budget in bytes: configured, or {@link #AUTO_BUDGET_SHARE} of the maximum heap. */
    static long budgetBytes(ResourceLimits limits) {
        return limits.memoryBudgetBytes() > 0 ? limits.memoryBudgetBytes()
                : (long) (Runtime.getRuntime().maxMemory() * AUTO_BUDGET_SHARE);
    }

    /** The worst-case heap a document needs, from its declared sizes; the base alone if they are unknown. */
    static long estimateBytes(ZipPackage.DeclaredSizes sizes) {
        if (sizes == null) {
            return BASE_BYTES; // not a ZIP: refused by validation before anything heavy runs
        }
        return BASE_BYTES + sizes.xmlBytes() * HEAP_PER_XML_BYTE + sizes.totalBytes() * HEAP_PER_PACKAGE_BYTE;
    }

    /**
     * Reserves {@code docx}'s estimate, waiting for room until the deadline.
     *
     * @throws ResourceLimitExceededError {@code MEMORY_BUDGET_EXCEEDED} when the estimate exceeds the
     *                                    whole budget, or a declared size exceeds the XML limit
     * @throws DocumentTimeoutError       when the deadline passes while waiting
     */
    public static Permit admit(byte[] docx, ResourceLimits limits, Deadline deadline, String tag) {
        ZipPackage.DeclaredSizes sizes = ZipPackage.declaredSizes(docx);
        if (sizes != null && sizes.xmlBytes() > limits.maxXmlBytes()) {
            // Refused before the estimate: the same answer ZipPackage.read would give, and no wait.
            throw new ResourceLimitExceededError("package XML parts expand to more than " + limits.maxXmlBytes()
                    + " bytes", "XML_TOTAL_TOO_LARGE");
        }
        long budget = budgetBytes(limits);
        long estimate = estimateBytes(sizes);
        if (estimate > budget) {
            throw new ResourceLimitExceededError("document needs an estimated " + estimate / (1024 * 1024)
                    + " MiB of heap; the budget is " + budget / (1024 * 1024) + " MiB", "MEMORY_BUDGET_EXCEEDED");
        }
        int budgetKib = (int) Math.min(Integer.MAX_VALUE, budget / 1024);
        int kib = (int) Math.max(1, Math.min(budgetKib, estimate / 1024));
        Semaphore gate = GATES.computeIfAbsent((long) budgetKib, k -> new Semaphore(budgetKib, true));
        if (!gate.tryAcquire(kib)) {
            LOG.info("memory_admission_wait {} estimate_mib={} available_mib={} budget_mib={}", tag, kib / 1024,
                    gate.availablePermits() / 1024, budgetKib / 1024);
            try {
                long waitNanos = (long) (Math.max(0, deadline.remaining()) * 1e9);
                if (!gate.tryAcquire(kib, waitNanos, TimeUnit.NANOSECONDS)) {
                    throw new DocumentTimeoutError("memory admission");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new DocumentProcessingError("memory admission interrupted", e);
            }
        }
        return new Permit(gate, kib);
    }
}
