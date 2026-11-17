package dev.filtsiap.ded.anonymizer.pycompat;

import java.math.BigDecimal;
import java.math.RoundingMode;

/** Python float formatting. */
public final class PyFloat {

    private PyFloat() {
    }

    /**
     * Python {@code repr(float)}: the shortest round-tripping digits (JDK 19+
     * {@code Double.toString} produces the same digits), laid out with Python's rules:
     * fixed notation for decimal exponents in [-4, 16), scientific otherwise.
     */
    public static String repr(double d) {
        if (Double.isNaN(d)) {
            return "nan";
        }
        if (Double.isInfinite(d)) {
            return d > 0 ? "inf" : "-inf";
        }
        if (d == 0.0) {
            return (Double.doubleToRawLongBits(d) < 0) ? "-0.0" : "0.0";
        }
        String sign = d < 0 ? "-" : "";
        BigDecimal exact = new BigDecimal(Double.toString(Math.abs(d))).stripTrailingZeros();
        String digits = exact.unscaledValue().toString();
        int decpt = digits.length() - exact.scale(); // position of the decimal point
        int exp = decpt - 1;
        StringBuilder out = new StringBuilder(sign);
        if (exp >= -4 && exp < 16) {
            if (decpt <= 0) {
                out.append("0.").append("0".repeat(-decpt)).append(digits);
            } else if (decpt >= digits.length()) {
                out.append(digits).append("0".repeat(decpt - digits.length())).append(".0");
            } else {
                out.append(digits, 0, decpt).append('.').append(digits.substring(decpt));
            }
        } else {
            out.append(digits.charAt(0));
            if (digits.length() > 1) {
                out.append('.').append(digits.substring(1));
            }
            out.append('e').append(exp < 0 ? '-' : '+');
            String e = Integer.toString(Math.abs(exp));
            out.append(e.length() < 2 ? "0" + e : e);
        }
        return out.toString();
    }

    /** Python {@code f"{d:.Nf}"}: round-half-even on the exact binary value, like CPython. */
    public static String fixed(double d, int decimals) {
        if (Double.isNaN(d)) {
            return "nan";
        }
        if (Double.isInfinite(d)) {
            return d > 0 ? "inf" : "-inf";
        }
        String s = new BigDecimal(d).setScale(decimals, RoundingMode.HALF_EVEN).toPlainString();
        if (d < 0 || (d == 0.0 && Double.doubleToRawLongBits(d) < 0)) {
            if (!s.startsWith("-")) {
                s = "-" + s;
            }
        }
        return s;
    }
}
