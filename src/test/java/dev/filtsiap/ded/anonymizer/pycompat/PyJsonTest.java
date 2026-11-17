package dev.filtsiap.ded.anonymizer.pycompat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** json.dumps/json.loads compatibility: JSON reaches prompts and hashes byte for byte. */
class PyJsonTest {

    @Test
    void dumpsMatchesPythonDefaults() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("text", "ΑΦΜ \"x\"");
        m.put("n", List.of(1, 0.1, 1e16, true));
        m.put("none", null);
        assertEquals("{\"text\": \"ΑΦΜ \\\"x\\\"\", \"n\": [1, 0.1, 1e+16, true], \"none\": null}", PyJson.dumps(m));
    }

    @Test
    void compactSeparatorsForHttpResponses() {
        assertEquals("{\"a\":[1,2]}", PyJson.dumps(Map.of("a", List.of(1, 2)), PyJson.COMPACT_SEPARATORS, false));
    }

    @Test
    void loadsAcceptsWhatPythonAccepts() throws Exception {
        Map<?, ?> m = (Map<?, ?>) PyJson.loads("{\"a\": 1, \"a\": NaN}");
        assertTrue(Double.isNaN(((Number) m.get("a")).doubleValue())); // duplicate key: last wins
    }

    @Test
    void loadsRejectsTrailingGarbage() {
        assertThrows(PyJson.JsonDecodeError.class, () -> PyJson.loads("[1] x"));
    }

    @Test
    void floatReprIsShortestRoundTrip() {
        assertEquals("60.0", PyFloat.repr(60.0));
        assertEquals("1e-05", PyFloat.repr(0.00001));
        assertEquals("0.2", PyFloat.fixed(0.25, 1)); // round-half-even on the binary value
    }
}
