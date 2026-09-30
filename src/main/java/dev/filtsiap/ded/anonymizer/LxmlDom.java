package dev.filtsiap.ded.anonymizer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.jsoup.Jsoup;
import org.jsoup.parser.Parser;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * lxml behaviour on top of the JDK DOM, for {@code docx_engine} and {@code postcheck}.
 *
 * <p>lxml models text as {@code element.text} (text before the first child) and
 * {@code child.tail} (text after a child). In the DOM both are Text nodes. lxml's child list
 * and child indexes count elements, comments, processing instructions and entity references,
 * never text; {@link #children} reproduces that, so element paths are identical. lxml's
 * {@code remove(child)} drops the child's tail with it; {@link #removeWithTail} does the same.
 *
 * <p>Parsing: strict ({@link #parseStrict}) is the JDK parser with external entities and
 * network access disabled (lxml: {@code resolve_entities=False, no_network=True}). CDATA is
 * coalesced into text, as lxml's default {@code strip_cdata=True}. Recovery
 * ({@link #parseRecover}) first tries strict, then jsoup's lenient XML parser, standing in for
 * lxml {@code recover=True}. Serialization mirrors {@code etree.tostring(root,
 * encoding='UTF-8', xml_declaration=True)}.
 */
final class LxmlDom {

    private static final DocumentBuilderFactory FACTORY = newFactory();
    private static final Pattern XML_DECL_ENCODING =
            Pattern.compile("^<\\?xml[^>]*encoding\\s*=\\s*[\"']([A-Za-z0-9._-]+)[\"']");

    private LxmlDom() {
    }

    /** Raised where lxml raises {@code XMLSyntaxError}. */
    static final class XmlSyntaxError extends Exception {
        private static final long serialVersionUID = 1L;

        XmlSyntaxError(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private static DocumentBuilderFactory newFactory() {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        f.setCoalescing(true);
        f.setExpandEntityReferences(false);
        f.setXIncludeAware(false);
        f.setValidating(false);
        try {
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("XML parser does not support secure configuration", e);
        }
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return f;
    }

    // ------------------------------------------------------------------ parsing

    /** Strict parse; returns the document element. */
    static Element parseStrict(byte[] blob) throws XmlSyntaxError {
        try {
            DocumentBuilder builder;
            synchronized (FACTORY) {
                builder = FACTORY.newDocumentBuilder();
            }
            builder.setErrorHandler(new ErrorHandler() {
                @Override
                public void warning(SAXParseException e) {
                    // lxml does not fail on warnings either.
                }

                @Override
                public void error(SAXParseException e) throws SAXException {
                    throw e;
                }

                @Override
                public void fatalError(SAXParseException e) throws SAXException {
                    throw e;
                }
            });
            Document doc = builder.parse(new ByteArrayInputStream(blob));
            Element root = doc.getDocumentElement();
            if (root == null) {
                throw new XmlSyntaxError("Document is empty", null);
            }
            recordAttributeOrder(root, blob);
            return root;
        } catch (SAXParseException e) {
            throw new XmlSyntaxError(e.getMessage() + ", line " + e.getLineNumber() + ", column "
                    + e.getColumnNumber(), e);
        } catch (SAXException | IOException e) {
            throw new XmlSyntaxError(String.valueOf(e.getMessage()), e);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Recovering parse: the strict result when the XML is well formed, otherwise jsoup's
     * lenient XML tree. Returns null when nothing usable comes out (lxml returns None).
     */
    static Element parseRecover(byte[] blob) {
        try {
            return parseStrict(blob);
        } catch (XmlSyntaxError strictFailure) {
            try {
                String text = rewriteReferences(trimTruncatedTag(decode(blob)));
                org.jsoup.nodes.Document soup = Jsoup.parse(text, "", Parser.xmlParser());
                org.jsoup.nodes.Element top = soup.children().isEmpty() ? null : soup.child(0);
                if (top == null) {
                    return null;
                }
                Document dom;
                synchronized (FACTORY) {
                    dom = FACTORY.newDocumentBuilder().newDocument();
                }
                List<Node> roots = convert(top, dom, new java.util.HashMap<>(Map.of("xml", XMLConstants.XML_NS_URI)));
                Element root = roots.stream().filter(n -> n instanceof Element).map(n -> (Element) n).findFirst().orElse(null);
                if (root == null) {
                    return null;
                }
                dom.appendChild(root);
                return root;
            } catch (RuntimeException | ParserConfigurationException recoveryFailure) {
                return null;
            }
        }
    }

    /** User-data key: the element's attribute qualified names in serialization order. */
    private static final String ATTR_ORDER = "lxml.attributeOrder";
    private static final javax.xml.stream.XMLInputFactory STAX = newStax();

    private static javax.xml.stream.XMLInputFactory newStax() {
        javax.xml.stream.XMLInputFactory f = javax.xml.stream.XMLInputFactory.newFactory();
        f.setProperty(javax.xml.stream.XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        f.setProperty(javax.xml.stream.XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false);
        f.setProperty(javax.xml.stream.XMLInputFactory.IS_NAMESPACE_AWARE, true);
        return f;
    }

    /**
     * The JDK DOM keeps attributes sorted by name; lxml keeps source order and writes namespace
     * declarations first. A StAX pass over the same bytes records that order per element (both
     * walk elements in document order), so {@link #serialize} can reproduce lxml's bytes.
     */
    private static void recordAttributeOrder(Element root, byte[] blob) {
        List<Element> elements = iterElements(root);
        int i = 0;
        try {
            javax.xml.stream.XMLStreamReader r = STAX.createXMLStreamReader(new ByteArrayInputStream(blob));
            try {
                while (r.hasNext()) {
                    if (r.next() != javax.xml.stream.XMLStreamConstants.START_ELEMENT) {
                        continue;
                    }
                    if (i >= elements.size()) {
                        return;
                    }
                    List<String> order = new ArrayList<>();
                    for (int n = 0; n < r.getNamespaceCount(); n++) {
                        String prefix = r.getNamespacePrefix(n);
                        order.add(prefix == null || prefix.isEmpty() ? "xmlns" : "xmlns:" + prefix);
                    }
                    for (int a = 0; a < r.getAttributeCount(); a++) {
                        String prefix = r.getAttributePrefix(a);
                        String local = r.getAttributeLocalName(a);
                        order.add(prefix == null || prefix.isEmpty() ? local : prefix + ":" + local);
                    }
                    elements.get(i++).setUserData(ATTR_ORDER, order, null);
                }
            } finally {
                r.close();
            }
        } catch (javax.xml.stream.XMLStreamException | RuntimeException e) {
            // Ordering is cosmetic (C14N-equal either way); fall back to DOM order.
        }
    }

    /** Private-use markers carrying an undefined entity name through jsoup, which would flatten it to text. */
    private static final char ENTITY_OPEN = '\uE000';
    private static final char ENTITY_CLOSE = '\uE001';
    private static final Pattern REFERENCE =
            Pattern.compile("&(?:#x[0-9A-Fa-f]*|#[0-9]*|[A-Za-z_:][A-Za-z0-9._:\\-]*)?(;?)");
    private static final java.util.Set<String> PREDEFINED = java.util.Set.of("amp", "lt", "gt", "quot", "apos");

    /**
     * libxml2's recovery for references, applied before jsoup: a malformed reference (no ';') is
     * deleted with its name; an undefined entity becomes an entity-reference node in text (so the
     * text after it is that node's tail, as in lxml) and is deleted in attribute values.
     * Comments, CDATA and processing instructions are left alone.
     */
    static String rewriteReferences(String xml) {
        StringBuilder out = new StringBuilder(xml.length());
        int i = 0;
        int n = xml.length();
        while (i < n) {
            if (xml.startsWith("<!--", i) || xml.startsWith("<![CDATA[", i) || xml.startsWith("<?", i)) {
                String end = xml.startsWith("<!--", i) ? "-->" : xml.startsWith("<?", i) ? "?>" : "]]>";
                int close = xml.indexOf(end, i);
                int stop = close < 0 ? n : close + end.length();
                out.append(xml, i, stop);
                i = stop;
            } else if (xml.charAt(i) == '<' && !canStartMarkup(xml, i + 1)) {
                i++; // libxml2: "StartTag: invalid element name"; the '<' is dropped, the text kept
            } else if (xml.charAt(i) == '<') {
                // A tag: rewrite only inside quoted attribute values.
                char quote = 0;
                while (i < n) {
                    char c = xml.charAt(i);
                    if (quote == 0 && c == '>') {
                        out.append(c);
                        i++;
                        break;
                    }
                    if (quote == 0 && (c == '"' || c == '\'')) {
                        quote = c;
                    } else if (c == quote) {
                        quote = 0;
                    } else if (quote != 0 && c == '&') {
                        i = reference(xml, i, out, false);
                        continue;
                    }
                    out.append(c);
                    i++;
                }
            } else if (xml.charAt(i) == '&') {
                i = reference(xml, i, out, true);
            } else {
                out.append(xml.charAt(i++));
            }
        }
        return out.toString();
    }

    private static boolean canStartMarkup(String xml, int i) {
        if (i >= xml.length()) {
            return true; // trimTruncatedTag already handled a trailing '<'
        }
        char c = xml.charAt(i);
        return c == '/' || c == '!' || c == '?' || c == '_' || c == ':' || Character.isLetter(c);
    }

    private static int reference(String xml, int at, StringBuilder out, boolean inText) {
        Matcher m = REFERENCE.matcher(xml).region(at, xml.length());
        m.lookingAt();
        String whole = m.group();
        if (m.group(1).isEmpty() || whole.equals("&;") || whole.equals("&#;") || whole.equals("&#x;")) {
            // Malformed: libxml2 drops "&" and the name it read, keeping a lone ";" if present.
            if (whole.endsWith(";") && whole.length() == 2) {
                out.append(';');
            }
            return m.end();
        }
        String name = whole.substring(1, whole.length() - 1);
        if (name.startsWith("#") || PREDEFINED.contains(name)) {
            out.append(whole); // jsoup decodes these exactly as libxml2 does
        } else if (inText) {
            out.append(ENTITY_OPEN).append(name).append(ENTITY_CLOSE);
        }
        return m.end();
    }

    private static final Pattern TRUNCATED_TAG =
            Pattern.compile("<([A-Za-z_][A-Za-z0-9._-]*)(?::([A-Za-z_][A-Za-z0-9._-]*))?[^<>]*\\z");

    /**
     * libxml2 recovery at a truncated end: a bare {@code <} or a closing tag vanishes; a start tag
     * cut after its name becomes an empty element ({@code "<w:t xml:sp"} gives {@code <w:t/>},
     * {@code "<w:"} gives {@code <w/>}).
     */
    static String trimTruncatedTag(String text) {
        int lastOpen = text.lastIndexOf('<');
        if (lastOpen < 0 || text.indexOf('>', lastOpen) >= 0) {
            return text;
        }
        String head = text.substring(0, lastOpen);
        Matcher m = TRUNCATED_TAG.matcher(text).region(lastOpen, text.length());
        if (!m.lookingAt()) {
            return head;
        }
        boolean complete = m.group(2) != null || !text.substring(m.end(1)).startsWith(":");
        String name = complete ? m.group(1) + (m.group(2) != null ? ":" + m.group(2) : "") : m.group(1);
        return head + "<" + name + "/>";
    }

    private static final Pattern XML_NAME = Pattern.compile("[A-Za-z_\\u00C0-\\uFFFD][A-Za-z0-9._\\-\\u00B7\\u00C0-\\uFFFD]*(?::[A-Za-z_\\u00C0-\\uFFFD][A-Za-z0-9._\\-\\u00B7\\u00C0-\\uFFFD]*)?");

    static boolean isXmlName(String name) {
        return XML_NAME.matcher(name).matches();
    }

    /**
     * jsoup nodes to DOM nodes (usually one; a split tag gives two; an unwrapped element gives
     * its children). Never throws for odd names, so a damaged part can never fall back to being
     * copied verbatim:
     * <ul>
     *   <li>a tag name holding {@code <} ({@code "<w:de<l a='1'>"}) becomes what libxml2 builds:
     *       an empty {@code <w:de/>} followed by {@code <l a='1'>...</l>};</li>
     *   <li>any other invalid element name is unwrapped: its children (and so its text) stay;</li>
     *   <li>attributes with invalid names are dropped.</li>
     * </ul>
     */
    private static List<Node> convert(org.jsoup.nodes.Node in, Document dom, Map<String, String> scope) {
        if (in instanceof org.jsoup.nodes.Element el) {
            String qname = el.tagName();
            int lt = qname.indexOf('<');
            if (lt >= 0) {
                List<Node> out = new ArrayList<>();
                String head = qname.substring(0, lt);
                if (isXmlName(head)) {
                    out.add(element(head, List.of(), dom, scope));
                }
                String tail = qname.substring(lt + 1);
                org.jsoup.nodes.Element renamed = el.clone().tagName(tail.isEmpty() ? "_" : tail);
                if (tail.isEmpty()) {
                    out.addAll(convertChildren(el, dom, scope));
                } else {
                    out.addAll(convert(renamed, dom, scope));
                }
                return out;
            }
            if (!isXmlName(qname)) {
                return convertChildren(el, dom, scope);
            }
            Map<String, String> inner = new java.util.HashMap<>(scope);
            List<org.jsoup.nodes.Attribute> attrs = new ArrayList<>();
            for (org.jsoup.nodes.Attribute a : el.attributes()) {
                if (!isXmlName(a.getKey())) {
                    continue;
                }
                attrs.add(a);
                if (a.getKey().equals("xmlns")) {
                    inner.put("", a.getValue());
                } else if (a.getKey().startsWith("xmlns:")) {
                    inner.put(a.getKey().substring(6), a.getValue());
                }
            }
            Element out = element(qname, attrs, dom, inner);
            for (Node child : convertChildren(el, dom, inner)) {
                out.appendChild(child);
            }
            return List.of(out);
        }
        if (in instanceof org.jsoup.nodes.TextNode t) {
            return textWithEntityRefs(t.getWholeText(), dom);
        }
        if (in instanceof org.jsoup.nodes.DataNode d) {
            return List.of(dom.createTextNode(d.getWholeData()));
        }
        if (in instanceof org.jsoup.nodes.Comment c) {
            String data = c.getData().replace("--", "- -");
            return List.of(dom.createComment(data));
        }
        if (in instanceof org.jsoup.nodes.XmlDeclaration pi && isXmlName(pi.name())) {
            return List.of(dom.createProcessingInstruction(pi.name(), pi.getWholeDeclaration()));
        }
        return List.of();
    }

    /** Splits text on the entity markers into Text and EntityReference nodes. */
    private static List<Node> textWithEntityRefs(String text, Document dom) {
        List<Node> out = new ArrayList<>();
        int pos = 0;
        while (true) {
            int open = text.indexOf(ENTITY_OPEN, pos);
            int close = open < 0 ? -1 : text.indexOf(ENTITY_CLOSE, open);
            if (close < 0) {
                if (pos < text.length()) {
                    out.add(dom.createTextNode(text.substring(pos)));
                }
                return out;
            }
            if (open > pos) {
                out.add(dom.createTextNode(text.substring(pos, open)));
            }
            out.add(dom.createEntityReference(text.substring(open + 1, close)));
            pos = close + 1;
        }
    }

    private static List<Node> convertChildren(org.jsoup.nodes.Element el, Document dom, Map<String, String> scope) {
        List<Node> out = new ArrayList<>();
        for (org.jsoup.nodes.Node child : el.childNodes()) {
            out.addAll(convert(child, dom, scope));
        }
        return out;
    }

    private static Element element(String qname, List<org.jsoup.nodes.Attribute> attrs, Document dom,
                                   Map<String, String> inner) {
        int colon = qname.indexOf(':');
        String ns = inner.get(colon < 0 ? "" : qname.substring(0, colon));
        Element out;
        if (ns != null && !ns.isEmpty()) {
            out = dom.createElementNS(ns, qname);
        } else if (colon < 0) {
            out = dom.createElementNS(null, qname);
        } else {
            out = dom.createElement(qname); // unbound prefix: kept literally, as lxml recovery does
        }
        List<String> order = new ArrayList<>();
        attrs.stream().filter(a -> a.getKey().equals("xmlns") || a.getKey().startsWith("xmlns:")).forEach(a -> order.add(a.getKey()));
        attrs.stream().filter(a -> !(a.getKey().equals("xmlns") || a.getKey().startsWith("xmlns:"))).forEach(a -> order.add(a.getKey()));
        out.setUserData(ATTR_ORDER, order, null);
        for (org.jsoup.nodes.Attribute a : attrs) {
            String key = a.getKey();
            int c = key.indexOf(':');
            try {
                if (key.equals("xmlns") || key.startsWith("xmlns:")) {
                    out.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, key, a.getValue());
                } else if (c > 0 && inner.containsKey(key.substring(0, c))) {
                    out.setAttributeNS(inner.get(key.substring(0, c)), key, a.getValue());
                } else if (c < 0) {
                    out.setAttributeNS(null, key, a.getValue());
                } else {
                    out.setAttribute(key, a.getValue());
                }
            } catch (org.w3c.dom.DOMException invalid) {
                // An attribute the DOM refuses (e.g. a bad namespace combination) is dropped.
            }
        }
        return out;
    }

    private static String decode(byte[] blob) {
        if (blob.length >= 3 && (blob[0] & 0xFF) == 0xEF && (blob[1] & 0xFF) == 0xBB && (blob[2] & 0xFF) == 0xBF) {
            return new String(blob, 3, blob.length - 3, StandardCharsets.UTF_8);
        }
        if (blob.length >= 2 && (blob[0] & 0xFF) == 0xFF && (blob[1] & 0xFF) == 0xFE) {
            return new String(blob, 2, blob.length - 2, StandardCharsets.UTF_16LE);
        }
        if (blob.length >= 2 && (blob[0] & 0xFF) == 0xFE && (blob[1] & 0xFF) == 0xFF) {
            return new String(blob, 2, blob.length - 2, StandardCharsets.UTF_16BE);
        }
        String head = new String(blob, 0, Math.min(blob.length, 200), StandardCharsets.ISO_8859_1);
        Matcher m = XML_DECL_ENCODING.matcher(head);
        if (m.find()) {
            try {
                return new String(blob, Charset.forName(m.group(1)));
            } catch (RuntimeException unknownCharset) {
                // fall through to UTF-8
            }
        }
        return new String(blob, StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ tags

    /** lxml {@code element.tag}: Clark notation {@code {ns}local}, or the bare name. */
    static String tag(Element e) {
        String ns = e.getNamespaceURI();
        String local = e.getLocalName() != null ? e.getLocalName() : e.getNodeName();
        return ns == null ? local : "{" + ns + "}" + local;
    }

    static boolean is(Node n, String ns, String local) {
        return n instanceof Element e && ns.equals(e.getNamespaceURI()) && local.equals(e.getLocalName());
    }

    /** lxml {@code QName(element).localname}. */
    static String localName(Element e) {
        return e.getLocalName() != null ? e.getLocalName() : e.getNodeName();
    }

    /** lxml {@code element.get(name)} for an un-namespaced attribute, or null. */
    static String attr(Element e, String name) {
        Attr a = e.getAttributeNodeNS(null, name);
        if (a == null) {
            a = e.getAttributeNode(name);
        }
        return a == null ? null : a.getValue();
    }

    // ------------------------------------------------------------------ lxml children

    private static boolean isLxmlChild(Node n) {
        short t = n.getNodeType();
        return t == Node.ELEMENT_NODE || t == Node.COMMENT_NODE || t == Node.PROCESSING_INSTRUCTION_NODE
                || t == Node.ENTITY_REFERENCE_NODE;
    }

    private static boolean isText(Node n) {
        short t = n.getNodeType();
        return t == Node.TEXT_NODE || t == Node.CDATA_SECTION_NODE;
    }

    /** lxml {@code list(element)}: elements, comments, PIs and entity references. */
    static List<Node> children(Node parent) {
        List<Node> out = new ArrayList<>();
        for (Node c = parent.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (isLxmlChild(c)) {
                out.add(c);
            }
        }
        return out;
    }

    /** Direct child elements only (lxml children filtered by {@code isinstance(tag, str)}). */
    static List<Element> childElements(Node parent) {
        List<Element> out = new ArrayList<>();
        for (Node c = parent.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (c instanceof Element e) {
                out.add(e);
            }
        }
        return out;
    }

    /** Direct child elements with the given namespace and local name (XPath {@code w:tr}). */
    static List<Element> childElements(Node parent, String ns, String local) {
        return childElements(parent).stream().filter(e -> is(e, ns, local)).toList();
    }

    /** lxml {@code element.getparent()}: null for the root and for a detached node. */
    static Element parent(Node n) {
        return n.getParentNode() instanceof Element p ? p : null;
    }

    /** lxml {@code element.iter()} filtered to elements: self then descendants, document order. */
    static List<Element> iterElements(Element root) {
        List<Element> out = new ArrayList<>();
        collect(root, out);
        return out;
    }

    private static void collect(Element e, List<Element> out) {
        out.add(e);
        for (Node c = e.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (c instanceof Element child) {
                collect(child, out);
            }
        }
    }

    /** XPath {@code .//ns:local}: descendants (not self), document order. */
    static List<Element> descendants(Element root, String ns, String local) {
        List<Element> out = new ArrayList<>();
        NodeList list = root.getElementsByTagNameNS(ns, local);
        for (int i = 0; i < list.getLength(); i++) {
            out.add((Element) list.item(i));
        }
        return out;
    }

    // ------------------------------------------------------------------ text and tail

    /** lxml {@code element.text}: text before the first lxml child; null when there is none. */
    static String text(Element e) {
        StringBuilder sb = null;
        for (Node c = e.getFirstChild(); c != null && isText(c); c = c.getNextSibling()) {
            if (sb == null) {
                sb = new StringBuilder();
            }
            sb.append(c.getNodeValue());
        }
        return sb == null ? null : sb.toString();
    }

    /** lxml {@code element.text = value}; an empty string keeps an empty text (serializes as {@code <a></a>}). */
    static void setText(Element e, String value) {
        Node c = e.getFirstChild();
        while (c != null && isText(c)) {
            Node next = c.getNextSibling();
            e.removeChild(c);
            c = next;
        }
        if (value != null) {
            e.insertBefore(e.getOwnerDocument().createTextNode(value), e.getFirstChild());
        }
    }

    /** lxml {@code child.text = value} followed by removing every lxml child: the element holds only {@code value}. */
    static void replaceContentWithText(Element e, String value) {
        while (e.getFirstChild() != null) {
            e.removeChild(e.getFirstChild());
        }
        e.appendChild(e.getOwnerDocument().createTextNode(value));
    }

    /** lxml {@code parent.remove(child)}: removes the child and its tail text. */
    static void removeWithTail(Node child) {
        Node parent = child.getParentNode();
        if (parent == null) {
            return;
        }
        Node next = child.getNextSibling();
        while (next != null && isText(next)) {
            Node after = next.getNextSibling();
            parent.removeChild(next);
            next = after;
        }
        parent.removeChild(child);
    }

    /**
     * {@code docx_engine._unwrap_element}: the element's text, children (with their tails) and
     * tail take its place. In the DOM that is exactly "move every child node up, drop the element".
     */
    static void unwrap(Element element) {
        Node parent = element.getParentNode();
        if (!(parent instanceof Element)) {
            return;
        }
        while (element.getFirstChild() != null) {
            parent.insertBefore(element.getFirstChild(), element);
        }
        parent.removeChild(element);
    }

    /** {@code docx_engine._drop_element}: removes the element and its content, keeps its tail in place. */
    static void dropKeepingTail(Element element) {
        Node parent = element.getParentNode();
        if (!(parent instanceof Element)) {
            return;
        }
        parent.removeChild(element);
    }

    /** lxml {@code "".join(root.itertext())}: all descendant text, comments and PIs excluded. */
    static String itertext(Element root) {
        StringBuilder sb = new StringBuilder();
        appendText(root, sb);
        return sb.toString();
    }

    private static void appendText(Node n, StringBuilder sb) {
        for (Node c = n.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (isText(c)) {
                sb.append(c.getNodeValue());
            } else if (c instanceof Element) {
                appendText(c, sb);
            }
        }
    }

    // ------------------------------------------------------------------ element paths

    /** {@code docx_engine._element_path}: child indexes (lxml counting) from root to element. */
    static String elementPath(Element root, Element element) {
        if (element == root) {
            return "/";
        }
        List<String> parts = new ArrayList<>();
        Node current = element;
        while (current != null && current != root) {
            Element parent = parent(current);
            if (parent == null) {
                break;
            }
            parts.add(Integer.toString(indexOf(parent, current)));
            current = parent;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = parts.size() - 1; i >= 0; i--) {
            sb.append('/').append(parts.get(i));
        }
        return sb.length() == 0 ? "/" : sb.toString();
    }

    private static int indexOf(Node parent, Node child) {
        int i = 0;
        for (Node c = parent.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (c == child) {
                return i;
            }
            if (isLxmlChild(c)) {
                i++;
            }
        }
        throw new IllegalArgumentException("not a child");
    }

    /** {@code docx_engine._find_by_element_path}: null for any invalid path. */
    static Element findByElementPath(Element root, String path) {
        if (path.equals("/")) {
            return root;
        }
        if (!path.startsWith("/")) {
            return null;
        }
        Node current = root;
        String trimmed = dev.filtsiap.ded.anonymizer.pycompat.PyStr.strip(path, "/");
        for (String token : trimmed.split("/", -1)) {
            if (token.isEmpty()) {
                return null;
            }
            int index;
            try {
                index = dev.filtsiap.ded.anonymizer.pycompat.PyNumber.parseInt(token)
                        .map(java.math.BigInteger::intValueExact).orElseThrow(NumberFormatException::new);
            } catch (NumberFormatException | ArithmeticException e) {
                return null;
            }
            List<Node> kids = children(current);
            if (index < 0 || index >= kids.size()) {
                return null;
            }
            current = kids.get(index);
        }
        return current instanceof Element e ? e : null;
    }

    // ------------------------------------------------------------------ serialization

    /** {@code etree.tostring(root, encoding='UTF-8', xml_declaration=True)}. */
    static byte[] serialize(Element root) {
        StringBuilder sb = new StringBuilder("<?xml version='1.0' encoding='UTF-8'?>\n");
        write(root, sb);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void write(Node n, StringBuilder sb) {
        switch (n.getNodeType()) {
            case Node.ELEMENT_NODE -> {
                Element e = (Element) n;
                sb.append('<').append(e.getNodeName());
                for (Attr a : orderedAttributes(e)) {
                    sb.append(' ').append(a.getName()).append("=\"");
                    escapeAttr(a.getValue(), sb);
                    sb.append('"');
                }
                if (e.getFirstChild() == null) {
                    sb.append("/>");
                } else {
                    sb.append('>');
                    for (Node c = e.getFirstChild(); c != null; c = c.getNextSibling()) {
                        write(c, sb);
                    }
                    sb.append("</").append(e.getNodeName()).append('>');
                }
            }
            case Node.TEXT_NODE, Node.CDATA_SECTION_NODE -> escapeText(n.getNodeValue(), sb);
            case Node.COMMENT_NODE -> sb.append("<!--").append(n.getNodeValue()).append("-->");
            case Node.PROCESSING_INSTRUCTION_NODE -> {
                String data = n.getNodeValue();
                sb.append("<?").append(n.getNodeName());
                if (data != null && !data.isEmpty()) {
                    sb.append(' ').append(data);
                }
                sb.append("?>");
            }
            case Node.ENTITY_REFERENCE_NODE -> sb.append('&').append(n.getNodeName()).append(';');
            default -> {
                // Document types and other node kinds are not part of tostring(root).
            }
        }
    }

    private static List<Attr> orderedAttributes(Element e) {
        NamedNodeMap attrs = e.getAttributes();
        List<Attr> all = new ArrayList<>();
        for (int i = 0; i < attrs.getLength(); i++) {
            all.add((Attr) attrs.item(i));
        }
        Object recorded = e.getUserData(ATTR_ORDER);
        if (!(recorded instanceof List<?> order)) {
            return all;
        }
        List<Attr> out = new ArrayList<>();
        for (Object name : order) {
            for (Attr a : all) {
                if (a.getName().equals(name) && !out.contains(a)) {
                    out.add(a);
                }
            }
        }
        for (Attr a : all) {
            if (!out.contains(a)) {
                out.add(a);
            }
        }
        return out;
    }

    private static void escapeText(String s, StringBuilder sb) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '&' -> sb.append("&amp;");
                case '\r' -> sb.append("&#13;");
                default -> sb.append(c);
            }
        }
    }

    private static void escapeAttr(String s, StringBuilder sb) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '&' -> sb.append("&amp;");
                case '"' -> sb.append("&quot;");
                case '\n' -> sb.append("&#10;");
                case '\r' -> sb.append("&#13;");
                case '\t' -> sb.append("&#9;");
                default -> sb.append(c);
            }
        }
    }

    /** A new document holding {@code <prefix:local xmlns:prefix="ns"/>} (lxml {@code etree.Element(tag, nsmap=...)}). */
    static Element newRoot(String ns, String prefix, String local) {
        try {
            Document doc;
            synchronized (FACTORY) {
                doc = FACTORY.newDocumentBuilder().newDocument();
            }
            Element root = doc.createElementNS(ns, prefix + ":" + local);
            root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:" + prefix, ns);
            doc.appendChild(root);
            return root;
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException(e);
        }
    }
}
