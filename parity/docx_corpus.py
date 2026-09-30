"""Builds synthetic DOCX packages (invented content only) exercising docx_engine edge cases."""
import random, zipfile, io
from corpus import document, afm, name, phone, iban_gr
W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
def esc(s): return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
def runs(text, rnd):
    # split a paragraph into several runs at random points, sometimes with odd content
    out=[]; i=0
    while i < len(text):
        j=min(len(text), i+rnd.randint(1,15))
        chunk=text[i:j]; kind=rnd.random()
        if kind<0.05: out.append(f'<w:r><w:t><![CDATA[{chunk}]]></w:t></w:r>')
        elif kind<0.10: out.append(f'<w:r><w:rPr><w:vanish/></w:rPr><w:t>{esc(chunk)}</w:t></w:r>')
        elif kind<0.15: out.append(f'<w:ins w:id="1" w:author="X"><w:r><w:t xml:space="preserve">{esc(chunk)}</w:t></w:r></w:ins>')
        elif kind<0.20: out.append(f'<w:del w:id="2" w:author="X"><w:r><w:delText>{esc(chunk)}</w:delText></w:r></w:del><w:r><w:t>{esc(chunk)}</w:t></w:r>')
        elif kind<0.23: out.append(f'<!-- c --><w:r><w:t>{esc(chunk)}</w:t></w:r><?pi data?>')
        elif kind<0.26: out.append(f'<w:r><w:t>{esc(chunk)}</w:t><w:tab/><w:br/></w:r>')
        elif kind<0.28: out.append(f'<w:commentRangeStart w:id="0"/><w:r><w:t>{esc(chunk)}</w:t></w:r><w:commentRangeEnd w:id="0"/><w:r><w:commentReference w:id="0"/></w:r>')
        elif kind<0.30: out.append(f'<w:moveTo w:id="3"><w:ins w:id="4"><w:r><w:t>{esc(chunk)}</w:t></w:r></w:ins></w:moveTo>')
        else: out.append(f'<w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">{esc(chunk)}</w:t></w:r>')
        i=j
    return "".join(out)
def para(text, rnd, pretty=False):
    sep = "\n    " if pretty else ""
    return f'<w:p>{sep}<w:pPr><w:jc w:val="both"/></w:pPr>{runs(text, rnd)}</w:p>' + ("\n  " if pretty else "")
def table(rnd, nested=False):
    hdr=rnd.choice([["ΑΦΜ","Όνομα","Τηλέφωνο"],["ΠΑΡΑΣΤΑΤΙΚΟ","ΗΜ/ΝΙΑ","ΦΠΑ"]])
    rows=[]
    for r in range(3):
        cells=[]
        for c,h in enumerate(hdr):
            val = h if r==0 else {"ΑΦΜ":afm(),"Όνομα":name(),"Τηλέφωνο":phone()}.get(h, f"ΤΙΜ. {rnd.randint(1,99)}")
            inner = table(rnd) if (nested and r==1 and c==0) else ""
            cells.append(f'<w:tc><w:tcPr/>{para(val, rnd)}{inner}</w:tc>')
        rows.append("<w:tr>"+"".join(cells)+"</w:tr>")
    return "<w:tbl><w:tblPr/>"+"".join(rows)+"</w:tbl>"
EXTRA = ["Οδός Ἀθηνᾶς ά (oxia) και α\u0301 αποσυντεθειμένο", "emoji 😀 και ΑΦΜ {afm} μετά", "γραμμή με\rcarriage return & αμπερσάντ < >", "NBSP\u00a0εδώ\u00a0ΑΦΜ {afm}", "τηλ. 2101234567 και IBAN {iban}"]
def build(seed, damaged_header=False, stored=False, comments=True, custom=True):
    rnd=random.Random(seed); random.seed(seed)
    paras=document(seed) + [e.format(afm=afm(), iban=iban_gr()) for e in EXTRA]
    body = "".join(para(p, rnd, pretty=rnd.random()<0.3) for p in paras[:6]) + table(rnd, nested=rnd.random()<0.4) + "".join(para(p, rnd) for p in paras[6:])
    doc = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document {W} xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>{body}<w:sectPr/></w:body></w:document>'
    header = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:hdr {W}>{para("Κεφαλίδα "+name()+" ΑΦΜ "+afm(), rnd)}</w:hdr>'
    if damaged_header: header = header[:len(header)-25]  # truncated XML -> recovery parser
    footer = f'<?xml version="1.0" encoding="UTF-8"?><w:ftr {W}>{para("Υποσέλιδο σελ. 1 "+phone(), rnd)}</w:ftr>'
    foot = f'<w:footnotes {W}><w:footnote w:id="1">{para("Υποσημείωση με email x.y@gmail.com", rnd)}</w:footnote></w:footnotes>'
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            f'<dc:creator>{name()}</dc:creator><cp:lastModifiedBy>{name()}<!--x--></cp:lastModifiedBy><dc:title>Απόφαση</dc:title>'
            '<dcterms:created xsi:type="dcterms:W3CDTF">2024-05-01T10:00:00Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2024-05-02T10:00:00Z</dcterms:modified></cp:coreProperties>')
    app = '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Template>Normal.dotm</Template><Company>Ιδιωτική Εταιρεία</Company><Pages>1</Pages></Properties>'
    ct = ('<?xml version="1.0" encoding="UTF-8"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n  <Default Extension="xml" ContentType="application/xml"/>\n'
          '  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>\n'
          '  <Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>\n</Types>')
    rels = ('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>\n'
            '  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>\n</Relationships>')
    comm = f'<w:comments {W}><w:comment w:id="0" w:author="{name()}">{para("σχόλιο", rnd)}</w:comment></w:comments>'
    custom_xml = '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"><property name="Owner"><vt:lpwstr xmlns:vt="x">A</vt:lpwstr></property></Properties>'
    parts = [("[Content_Types].xml",ct),("_rels/.rels",rels),("word/document.xml",doc),("word/header1.xml",header),("word/footer1.xml",footer),
             ("word/footnotes.xml",foot),("docProps/core.xml",core),("docProps/app.xml",app),("word/media/image1.png",b"\x89PNG fake bytes")]
    if comments: parts.append(("word/comments.xml",comm))
    if custom: parts.append(("docProps/custom.xml",custom_xml))
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,"w") as z:
        for i,(n,data) in enumerate(parts):
            zi=zipfile.ZipInfo(n, date_time=(2024,5,1,10,0,i*2))
            zi.compress_type = zipfile.ZIP_STORED if (stored and i%2) else zipfile.ZIP_DEFLATED
            z.writestr(zi, data if isinstance(data,bytes) else data.encode("utf-8"))
    return buf.getvalue()
