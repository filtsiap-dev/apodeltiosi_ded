package dev.filtsiap.ded.anonymizer;

/**
 * Pointer from one extracted character back into the XML (port of {@code XmlCharRef}).
 *
 * @param partName     package part, e.g. {@code word/document.xml}
 * @param textNodePath child-index path of the {@code w:t} element, or a synthetic
 *                     {@code <w:tab/>}/{@code <w:br/>}/{@code <w:cr/>} marker
 * @param charIndex    code-point index into that element's text
 */
public record XmlCharRef(String partName, String textNodePath, int charIndex) {
}
