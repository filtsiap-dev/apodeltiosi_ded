package dev.filtsiap.ded.anonymizer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class DetectorsTest {

    static final FileConfig FILES = Config.loadFileConfig(Path.of("config"));
    static final DetectorRules RULES = FILES.rules();

    static TextUnit unit(String text) {
        return new TextUnit("u0", "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(0));
    }

    /** The texts of the rule spans {@code detectAll} gives one paragraph, in the given categories, in detection order. */
    static List<String> texts(String paragraph, SpanCategory... categories) {
        List<SpanCategory> wanted = List.of(categories);
        return Detectors.detectAll(new DocumentData("d", List.of(unit(paragraph)), List.of(), List.of()), RULES)
                .resolverSpans().stream().filter(s -> wanted.contains(s.category()))
                .filter(s -> !s.detector().equals("public_service_gazetteer")) // rules, not the allowlist
                .map(Span::text).toList();
    }

    static Span only(String paragraph, SpanCategory category) {
        List<Span> spans = Detectors.detectAll(new DocumentData("d", List.of(unit(paragraph)), List.of(), List.of()),
                RULES).resolverSpans().stream().filter(s -> s.category() == category).toList();
        assertEquals(1, spans.size(), spans.toString());
        return spans.get(0);
    }

    @Test
    void everyRuleSpanIsDeterministic() {
        String text = "με ΑΦΜ " + TestDocx.validAfm("12345678") + ", ΑΤΑΚ 01234567890, Δήμου Λαμιέων, 01/02/1980";
        Detectors.DetectionResult r = Detectors.detectAll(new DocumentData("d", List.of(unit(text)), List.of(),
                List.of()), RULES);
        assertTrue(r.resolverSpans().stream().allMatch(s -> s.origin() == SpanOrigin.DETERMINISTIC));
        assertTrue(r.reviewHints().stream().allMatch(s -> s.origin() == SpanOrigin.DETERMINISTIC));
    }

    // ------------------------------------------------------------------ dates

    @Test
    void dateOfBirthIsAnOrdinaryDateNotAHardPreserve() {
        Span date = only("Ημερομηνία γέννησης 01/02/1980", SpanCategory.DATE);
        assertEquals("01/02/1980", date.text());
        assertFalse(Resolver.isHardPreserve(date, FILES.policy()));
        assertEquals(List.of(), texts("Ημερομηνία γέννησης 01/02/1980", SpanCategory.PROCEDURAL_DATE));
        // No birth cue at all is still not evidence of a procedural date.
        assertEquals(List.of("03/05/1981"), texts("Ο Νίκος Παπαδόπουλος, 03/05/1981, ΑΦΜ", SpanCategory.DATE));
    }

    @Test
    void onlyAnExplicitProceduralCueMakesAHardPreservedDate() {
        Span filed = only("ημερομηνία κατάθεσης: 15/03/2026", SpanCategory.PROCEDURAL_DATE);
        assertTrue(Resolver.isHardPreserve(filed, FILES.policy()));
        assertEquals(List.of("05/03/2026", "3 Μαρτίου 2026"), // numeric dates are detected first
                texts("Η πράξη εκδόθηκε στις 3 Μαρτίου 2026 και κοινοποιήθηκε στις 05/03/2026",
                        SpanCategory.PROCEDURAL_DATE));
        // "με ημερομηνία" is too weak to buy a hard tier.
        assertEquals(List.of("07/04/2025"), texts("με ημερομηνία 07/04/2025", SpanCategory.DATE));
    }

    // ------------------------------------------------------------------ field labels

    @Test
    void structuredIdSpansCoverTheValueAndLeaveTheLabel() {
        String afm = TestDocx.validAfm("12345678");
        assertEquals(afm, only("ΑΦΜ: " + afm, SpanCategory.AFM).text());
        assertEquals("01018512345", only("ΑΜΚΑ 01018512345", SpanCategory.AMKA).text());
    }

    @Test
    void fieldLabelsAreDetectedIndependentlyOfTheirValues() {
        String text = "με Α.Φ.Μ. " + TestDocx.validAfm("12345678")
                + ", κατοίκου Περιστερίου, οδός Ερμού αρ. 12, Τ.Κ. 12345";
        assertEquals(List.of("Α.Φ.Μ.", "κατοίκου", "οδός", "αρ.", "Τ.Κ."), texts(text, SpanCategory.FIELD_LABEL));
        assertTrue(Resolver.isHardPreserve(only("ΑΤΑΚ 01234567890", SpanCategory.FIELD_LABEL), FILES.policy()));
        assertEquals(List.of("Τηλ.", "E-mail", "Fax"),
                texts("Τηλ.: 2101234567, E-mail: someone@example.com, Fax 2101234568", SpanCategory.FIELD_LABEL));
    }

    @Test
    void aFieldLabelNeedsEvidenceOfItsValue() {
        // "ΙΒΑΝ" is also a first name; only an IBAN-shaped value makes it a label.
        assertEquals(List.of("IBAN"), texts("Με δικαιούχο τον ΙΒΑΝ ΠΕΤΡΟΦ, ΙΒΑΝ 45 ετών, IBAN GR16 0110 1250 0000",
                SpanCategory.FIELD_LABEL));
        assertEquals(List.of(), texts("το επώνυμο IBANEZ 12 και Α.Τ.Κ. ΑΛΕΞΑΝΔΡΟΣ", SpanCategory.FIELD_LABEL));
        assertEquals(List.of(), texts("ο αφμ 123", SpanCategory.FIELD_LABEL)); // case-sensitive
    }

    // ------------------------------------------------------------------ new categories

    @Test
    void propertyIdsAreHardRedactsSplitPerValue() {
        assertEquals(List.of("01234567890", "01234567891", "09876543210"),
                texts("ΑΤΑΚ 01234567890, 01234567891 και 09876543210", SpanCategory.PROPERTY_ID));
        // An all-zero ΚΑΕΚ subdivision stays visible, as a hard preserve of its own; a real one goes
        // with the root.
        String kaek = "ΚΑΕΚ 050011122233/0/0 και ΚΑΕΚ 050011122234/1/2";
        assertEquals(List.of("050011122233", "050011122234/1/2"), texts(kaek, SpanCategory.PROPERTY_ID));
        Span suffix = Detectors.detectAll(new DocumentData("d", List.of(unit(kaek)), List.of(), List.of()), RULES)
                .resolverSpans().stream().filter(s -> s.detector().equals("kaek_zero_suffix")).findFirst().orElseThrow();
        assertEquals("/0/0", suffix.text());
        assertTrue(Resolver.isHardPreserve(suffix, FILES.policy()));
        assertEquals(List.of("45α", "46Β"), texts("Ο.Τ. 45α και 46Β", SpanCategory.PROPERTY_ID));
        // A notice number keeps its trailing date or year.
        assertEquals(List.of("7654321", "1234"), texts(
                "αριθμό ειδοποίησης 7654321/01-04-2026 και αριθμό ειδοποίησης 1234/2026", SpanCategory.PROPERTY_ID));
        assertTrue(Resolver.isHardRedact(only("Α.Χ.Κ. 12/34567", SpanCategory.PROPERTY_ID), FILES.policy()));
    }

    @Test
    void anAuthorityPlaceIsPartOfAPublicNameAndADistrictIsAnOrdinaryProposal() {
        String text = "Δήμου Λαμιέων και στη συνοικία Β΄ Λαμίας";
        List<Span> spans = Detectors.detectLocalities(unit(text), RULES);
        assertEquals(List.of("PUBLIC_SERVICE:PRESERVE:Δήμου Λαμιέων", "LOCALITY:REDACT:Λαμίας"), spans.stream()
                .map(s -> s.category().wire() + ":" + s.action() + ":" + s.text()).toList());
        assertTrue(Resolver.isHardPreserve(spans.get(0), FILES.policy()));
        assertFalse(Resolver.isHardRedact(spans.get(1), FILES.policy()) || Resolver.isHardPreserve(spans.get(1),
                FILES.policy()));
        assertEquals(List.of(), texts("ΔΟΥ Λαμίας", SpanCategory.LOCALITY)); // no Δ.Ο.Υ. cue
    }

    static final SpanCategory[] PLACES = {SpanCategory.PUBLIC_SERVICE, SpanCategory.PUBLIC_LOCALITY,
        SpanCategory.LOCALITY};

    @Test
    void theKeptPlaceIsBoundedSoItCannotShieldAName() {
        // The cue and the place; never the capitalized words that happen to follow.
        assertEquals(List.of("Δήμου Λαμιέων"), texts("του Δήμου Λαμιέων Γεώργιος Παπαδόπουλος",
                SpanCategory.PUBLIC_SERVICE));
        // A residence is kept only as a municipality and the region it ends in.
        assertEquals(List.of("Χαλανδρίου Αττικής"), texts("κατοίκου Χαλανδρίου Αττικής, οδός",
                SpanCategory.PUBLIC_LOCALITY));
        assertEquals(List.of("Νέας Σμύρνης Αττικής"), texts("κάτοικος Νέας Σμύρνης Αττικής.",
                SpanCategory.PUBLIC_LOCALITY));
        // A bare town is kept, but only as the whole run: never with the words after it, never a listed name.
        assertEquals(List.of("Θεσσαλονίκης"), texts("κάτοικος Θεσσαλονίκης.", PLACES));
        assertEquals(List.of(), texts("κάτοικος Λαμίας Γεώργιος Παπαδόπουλος.", PLACES));
        assertEquals(List.of(), texts("η κάτοικος Μαρία, που", PLACES));
        assertEquals(List.of(), texts("κατοίκου Λαμίας Αττικής Γεώργιου Παπαδόπουλου Αττικής.",
                PLACES)); // more than a place before the region
        // A region keeps its place only when it ENDS the run; anything after it ends the protection.
        assertEquals(List.of("Δήμου Χαλκιδέων Ευβοίας"), texts("του Δήμου Χαλκιδέων Ευβοίας.", PLACES));
        assertEquals(List.of("Δήμου Χαλκιδέων"), texts("του Δήμου Χαλκιδέων Ευβοίας Γεώργιος.", PLACES));
        // A two-word place opened by a toponym modifier is kept whole, with the region that ends the run.
        assertEquals(List.of("Δήμου Νέας Ιωνίας Μαγνησίας"), texts("του Δήμου Νέας Ιωνίας Μαγνησίας.", PLACES));
    }

    @Test
    void aMunicipalityWithItsRegionIsKeptAndEverythingElseOfTheAddressIsProposed() {
        String text = "κατοίκου Χαλανδρίου Αττικής, οδός Διομήδους αρ. 12.";
        Span residence = only(text, SpanCategory.PUBLIC_LOCALITY);
        assertEquals("Χαλανδρίου Αττικής", residence.text());
        assertTrue(Resolver.isHardPreserve(residence, FILES.policy()));
        assertTrue(texts(text, SpanCategory.PRIVATE_ADDRESS).stream().anyMatch(t -> t.startsWith("Διομήδους")));
        // A bare town after the cue is kept by policy (hard, like the town with its region); the street is proposed.
        Span town = only("κατοίκου Λαμίας, οδός Διομήδους", SpanCategory.PUBLIC_LOCALITY);
        assertEquals("Λαμίας", town.text());
        assertTrue(Resolver.isHardPreserve(town, FILES.policy()));
        assertEquals(List.of("Νέας Σμύρνης"), texts("κάτοικος Νέας Σμύρνης, οδός Ερμού 5", PLACES));
        assertEquals(List.of("Διομήδους"), texts("κατοίκου Λαμίας, οδός Διομήδους", SpanCategory.PRIVATE_ADDRESS));
        // A population is nobody's address: no span either way.
        assertEquals(List.of(), texts("οι κάτοικοι Χαλκίδας ζητούν", PLACES));
        // A street named after a region is a street: nothing of it is kept.
        assertEquals(List.of(), texts("οδός Κρήτης, Λαμία", PLACES));
    }

    // ------------------------------------------------------------------ v2 63ba018 detector geometry

    @Test
    void aResidenceAStreetItsNumberAndItsPostalCodeAreEachProposedAndTheLabelsStay() {
        String text = "κατοίκου Λαμίας, οδός Διομήδους αρ. 12, Τ.Κ. 15231.";
        List<String> address = texts(text, SpanCategory.PRIVATE_ADDRESS);
        assertEquals(List.of("Διομήδους", "12", "15231"), address); // the town itself is kept by policy
        assertEquals(List.of("Λαμίας"), texts(text, SpanCategory.PUBLIC_LOCALITY));
        assertTrue(address.stream().noneMatch(t -> t.contains("Τ.Κ") || t.contains("κατοίκου")), address.toString());
        // A residence that is a municipality AND more than its region gives the region back.
        assertEquals(List.of("Αγίας Παρασκευής Νέας"), texts("κατοίκου Αγίας Παρασκευής Νέας Αττικής.",
                SpanCategory.PRIVATE_ADDRESS));
    }

    @Test
    void aStreetNumberIsOnlyProposedAfterAStreetNameNeverAfterAnArticleOrASerial() {
        assertEquals(List.of(), texts("σύμφωνα με τις διατάξεις του αρ. 9 της ΠΟΛ 1234/2015",
                SpanCategory.PRIVATE_ADDRESS));
        assertEquals(List.of(), texts("των αρ. 99 έως 101 του ν. 4174/2013", SpanCategory.PRIVATE_ADDRESS));
        assertEquals(List.of(), texts("η υπ' αρ. 231/2020 δικαστική απόφαση", SpanCategory.PRIVATE_ADDRESS));
        assertTrue(texts("οδός Ερμού αρ. 5Α", SpanCategory.PRIVATE_ADDRESS).containsAll(List.of("Ερμού", "5Α")));
    }

    // ------------------------------------------------------------------ address span boundaries

    /** The PRIVATE_ADDRESS rule spans of one paragraph, each text once, in detection order. */
    static List<String> address(String paragraph) {
        return texts(paragraph, SpanCategory.PRIVATE_ADDRESS).stream().distinct().toList();
    }

    /** The confirmed over-reach: the original rule's capture ran from the place through the clause after it. */
    @Test
    void aResidenceProposalIsThePlaceNeverTheClauseAfterIt() {
        for (String text : List.of("Ο Νικόλαος Ιωάννου, κάτοικος Λαμίας, προσέφυγε κατά της πράξης.",
                "Ο Νικόλαος Ιωάννου, κάτοικος Λαμίας, προσέφυγε κατά της πράξης",
                "η προσφεύγουσα, κάτοικος Λαμίας και ο σύζυγός της", "κάτοικος Λαμίας\nπροσέφυγε",
                "κάτοικος Λαμίας\tΑριθμός Απόφασης: 3151", "κάτοικος Λαμίας (ν. Φθιώτιδας)")) {
            assertEquals(List.of("Λαμίας"), address(text), text);
        }
    }

    /** The confirmed boundary errors: "Ερμού αρ" (the label's own dot ended it) and "Ερμού, Τ" (a "Τ.Κ." after it). */
    @Test
    void aStreetProposalStopsBeforeItsNumberLabelAndItsPostalCode() {
        assertEquals(List.of("Ερμού", "5"), address("οδός Ερμού αρ. 5"));
        assertEquals(List.of("Ερμού", "5", "15231"), address("οδός Ερμού αρ.5,Τ.Κ.15231"));
        assertEquals(List.of("Ερμού", "15231"), address("οδός Ερμού, Τ.Κ. 15231"));
        assertEquals(List.of("Ερμού 5", "15231"), address("οδός Ερμού 5, Τ.Κ. 15231"));
        assertEquals(List.of("Λαμίας", "35100"), address("κάτοικος Λαμίας, Τ.Κ. 35100"));
        assertEquals(List.of("Αγίου Κωνσταντίνου 12", "10431"), address("οδός Αγίου Κωνσταντίνου 12 Τ.Κ. 10431"));
        assertEquals(List.of("Πανεπιστημίου 30", "10679"), address("οδός Πανεπιστημίου 30 και Τ.Κ. 10679, με ΑΦΜ"));
        assertEquals(List.of("Μαιζώνος 12"), address("οδός Μαιζώνος 12, άσκησε προσφυγή."));
        assertEquals(List.of("Ερμού 12-14"), address("στην οδό Ερμού 12-14, όπου"));
        for (String text : List.of("οδός Ερμού αρ. 5", "οδός Ερμού, Τ.Κ. 15231", "κάτοικος Λαμίας, Τ.Κ. 35100")) {
            assertTrue(address(text).stream().noneMatch(t -> t.contains(",") || t.endsWith("αρ") || t.endsWith("Τ")),
                    text);
        }
    }

    @Test
    void anAddressIsReadInAnyCaseAndAccentingAndAfterEveryStreetCue() {
        assertEquals(List.of("ΑΘΗΝΩΝ", "ΕΡΜΟΥ", "5", "15231"), address("ΚΑΤΟΙΚΟΣ ΑΘΗΝΩΝ, ΟΔΟΣ ΕΡΜΟΥ ΑΡ. 5, ΤΚ 15231"));
        assertEquals(List.of("Ερμου", "5"), address("οδός Ερμου αρ. 5"));
        assertEquals(List.of("Ερμού", "5"), address("Οδός Ερμού αρ. 5"));
        // The genitive and accusative street cues, a number without "αρ." and one after "αριθ." (3151, 3096).
        String inCapitals = "κατοίκου ΑΘΗΝΩΝ, επί της οδού ΒΕΛΒΕΝΔΟΥΣ 41, Τ.Κ. 11363, κατά";
        assertEquals(List.of("ΒΕΛΒΕΝΔΟΥΣ 41", "11363"), address(inCapitals));
        assertEquals(List.of("ΑΘΗΝΩΝ"), texts(inCapitals, SpanCategory.PUBLIC_LOCALITY)); // the town is kept
        assertEquals(List.of("Σμύρνης", "49"), address("να εδρεύει στην οδό Σμύρνης αρ. 49 στο Αιγάλεω"));
        assertEquals(List.of("Ακρίτα", "47", "24100"), address("οδός Ακρίτα αριθ. 47, ΤΚ 24100"));
        assertEquals(List.of("Κηφισίας 10"), address("Λεωφ. Κηφισίας 10"));
    }

    @Test
    void aStreetNameMayOpenWithAnInitialOrAnOrdinalAndAStreetAfterTheResidenceIsItsOwnSpan() {
        assertEquals(List.of("Ι. Μεταξά 12"), address("οδός Ι. Μεταξά 12"));
        assertEquals(List.of("28ης Οκτωβρίου 5"), address("οδός 28ης Οκτωβρίου 5"));
        assertEquals(List.of("Ν. Σμύρνης"), address("κάτοικος Ν. Σμύρνης"));
        // A street written after the place with no street cue is its own span, never one with the place, so a
        // decision to keep the residence locality never meets one redaction of both.
        assertEquals(List.of("Αθηνών", "Πατησίων 12", "10434"), address("κάτοικος Αθηνών, Πατησίων 12, Τ.Κ. 10434"));
    }

    @Test
    void whatIsNotAnAddressGetsNoAddressSpan() {
        assertEquals(List.of(), address("της ΠΕΡΙΟΔΟΥ ΙΑΝΟΥΑΡΙΟΥ αρ. 5")); // "ΟΔΟΥ" inside a word is no street cue
        assertEquals(List.of(), address("του άρθρου 5 αριθ. 47 του νόμου"));
        assertEquals(List.of(), address("η οδός διαφυγής"));
        assertEquals(List.of("Ερμού"), address("οδός Ερμού 5.000 ευρώ")); // an amount is no house number
        assertEquals(List.of("Ερμού"), address("οδός Ερμού 2020/123")); // nor is a serial
    }

    static TextUnit para(int index, String text) {
        return new TextUnit("u" + index, "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(index));
    }

    /**
     * The confirmed short-document defect: with no title line the header ran on into the appellant's own
     * paragraph, whose phone and e-mail cues made it a confident authority PRESERVE.
     */
    @Test
    void theAuthorityHeaderEndsWhereTheBodySpeaksOfAPrivateParty() {
        DocumentData doc = new DocumentData("d", List.of(para(0, "ΕΛΛΗΝΙΚΗ ΔΗΜΟΚΡΑΤΙΑ"),
                para(1, "Ταχ. Δ/νση : Φιλαδελφείας 8 και Σάμου"), para(2, "Τηλέφωνο: 2131312347"),
                para(3, "Ο προσφεύγων Γεώργιος Παπαδόπουλος, κάτοικος Λαμίας, τηλέφωνο 6912345678, e-mail "
                        + "giorgos@example.com, κατά της ΑΑΔΕ."),
                para(4, "Τηλέφωνο: 2131312348")), List.of(), List.of());
        // The authority's own lines keep their recommendation ("Φιλαδελφείας" is no private-party word).
        assertEquals(List.of("u0", "u1", "u2"), Detectors.detectAuthorityHeader(doc).stream().map(Span::unitId).toList());
        // A letter-spaced title ends the header as the plain one does.
        DocumentData spaced = new DocumentData("d", List.of(para(0, "ΕΛΛΗΝΙΚΗ ΔΗΜΟΚΡΑΤΙΑ"), para(1, "\tΑ Π Ο Φ Α Σ Η"),
                para(2, "Τηλέφωνο: 2131312347")), List.of(), List.of());
        assertEquals(List.of("u0"), Detectors.detectAuthorityHeader(spaced).stream().map(Span::unitId).toList());
    }

    @Test
    void aPatronymicKeepsItsArticleExceptAfterTheAppealCue() {
        assertEquals(List.of("του Γεωργίου Παπαδόπουλου"), texts("του Γεωργίου Παπαδόπουλου με Α.Φ.Μ. 246813570",
                SpanCategory.FATHER_NAME));
        assertEquals(List.of("του ΝΙΚΟΛΑΟΥ ΔΗΜΗΤΡΙΟΥ"), texts("του ΝΙΚΟΛΑΟΥ ΔΗΜΗΤΡΙΟΥ κατοίκου Λαμίας",
                SpanCategory.FATHER_NAME));
        // After "προσφυγή" the article belongs to the appeal: the gold keeps it.
        assertEquals(List.of("ΝΙΚΟΛΑΟΥ ΔΗΜΗΤΡΙΟΥ"), texts("η προσφυγή του ΝΙΚΟΛΑΟΥ ΔΗΜΗΤΡΙΟΥ με ΑΦΜ 094014201",
                SpanCategory.FATHER_NAME));
    }

    @Test
    void anHonorificIntroducesAnAppellantName() {
        assertEquals(List.of("Γεώργιος Παπαδόπουλος"), texts("ο κ. Γεώργιος Παπαδόπουλος δήλωσε",
                SpanCategory.APPELLANT_NAME));
        assertEquals(List.of("Αντωνίου"), texts("και του κου Αντωνίου", SpanCategory.APPELLANT_NAME));
        assertEquals(List.of(), texts("η καταγγελία εξετάστηκε", SpanCategory.APPELLANT_NAME)); // "κα" inside a word
    }

    @Test
    void referenceNumbersKeepTheirYearAndTheirLabel() {
        assertEquals(List.of("1234"), texts("αρ. πρωτ. 1234/2026", SpanCategory.PROTOCOL_NUMBER));
        assertEquals(List.of("123", "456"), texts("εντολή ελέγχου 123/2021 και εντολής μερικού ελέγχου 456/2022",
                SpanCategory.AUDIT_ORDER));
        assertEquals(List.of("1234"), texts("κατά της υπ' αριθ. 1234/2020 πράξης", SpanCategory.CHALLENGED_ACT_NUMBER));
        assertEquals(List.of("1234", "55"), texts("Τιμολόγιο 1234 και Α/Α 55", SpanCategory.INVOICE_NUMBER));
    }

    /**
     * Found by the real-model run of 3151: "με αριθ. ειδοποίησης 125440/2021 πράξη ... φόρου" proposed "ειδοπο", the
     * label's first letters, as the challenged act's number, and pass 2 followed it, leaving "......ίησης" in the
     * output. The act number must hold a digit; the abbreviated notice cue is a label, and its serial a notice number.
     */
    @Test
    void aNoticeLabelIsNeverAnActNumberAndItsSerialIsTheNoticeNumber() {
        for (String text : List.of("εκδόθηκε η με αριθ. ειδοποίησης 125440/2021 πράξη διοικητικού προσδιορισμού φόρου",
                "προσβάλλει την με αριθ. ειδοποίησης 46577/2026 (Α.Χ.Κ. 5069/141) πράξη διορθωτικού προσδιορισμού φόρου")) {
            assertEquals(List.of(), texts(text, SpanCategory.CHALLENGED_ACT_NUMBER), text);
            assertTrue(texts(text, SpanCategory.FIELD_LABEL).contains("αριθ. ειδοποίησης"), text);
        }
        Span notice = only("εκδόθηκε η με αριθ. ειδοποίησης 125440/2021 πράξη", SpanCategory.PROPERTY_ID);
        assertEquals("125440", notice.text()); // the year stays visible
        assertTrue(Resolver.isHardRedact(notice, FILES.policy()));
        // A real act number is still proposed, digits first or letters first.
        assertEquals(List.of("69"), texts("κατά της υπ’ αριθ. 69/26-02-2026 Οριστικής Πράξης", SpanCategory.CHALLENGED_ACT_NUMBER));
        assertEquals(List.of("Α.1165"), texts("της υπ’ αριθ. Α.1165/22.11.2022 Πράξης", SpanCategory.CHALLENGED_ACT_NUMBER));
        // The capitals heading of an act (3096's "ΑΡΙΘ. 52/2026 ΟΡΙΣΤΙΚΗ ΠΡΑΞΗ"), its year kept; never a label alone.
        assertEquals(List.of("52"), texts("ΑΡΙΘ. 52/2026 ΟΡΙΣΤΙΚΗ ΠΡΑΞΗ", SpanCategory.CHALLENGED_ACT_NUMBER));
        assertEquals(List.of(), texts("ΑΡΙΘ. ΠΡΩΤ. της Οριστικής Πράξης", SpanCategory.CHALLENGED_ACT_NUMBER));
        assertEquals(List.of(), texts("αριθ. 52/2026 ΟΡΙΣΤΙΚΗ ΠΡΑΞΗ", SpanCategory.CHALLENGED_ACT_NUMBER)); // lowercase: no cue
    }

    @Test
    void anAccountAfterTheBankCueIsProposed() {
        assertEquals(List.of("GR6401401230000000123456789"), texts("Τράπεζα GR6401401230000000123456789",
                SpanCategory.BANK_ACCOUNT));
        assertEquals(List.of("1234567890"), texts("στον λογαριασμό 1234567890 της εταιρείας", SpanCategory.BANK_ACCOUNT));
    }

    /** Found by the real-model run of 3096: the model kept these tails in one run and blanked them in another. */
    @Test
    void theVisibleTailOfAnAccountTheSourceMaskedWithXIsProposed() {
        assertEquals(List.of("1495", "7414"), texts("τα extrait της Ε.Τ.Ε. XXX 1495 και ΑΛΦΑ ΒΑΝΚ ΧΧΧ7414 και εκτύπωση",
                SpanCategory.BANK_ACCOUNT)); // Latin X, then Greek Χ
        Span tail = only("λογαριασμός XXX 1495", SpanCategory.BANK_ACCOUNT);
        assertEquals(SpanAction.REDACT, tail.action());
        assertFalse(Resolver.isHardRedact(tail, FILES.policy())); // an ordinary proposal: pass 2 decides
        // Two letters, letters inside a word, or a longer number: no tail.
        assertEquals(List.of(), texts("XX 1495, το ΤΑΧΧΧ 1495 και XXX 123456789", SpanCategory.BANK_ACCOUNT));
    }

    @Test
    void aBankNameIsKeptByPolicyAndOnlyTheAccountIsProposed() {
        // A name after "Τράπεζα" is the bank: kept (owner policy), and never read as an account number.
        for (String text : List.of("προς την Τράπεζα ΔΕΛΤΑ BANK A.E. όπως", "απόρρητο έγγραφο της τράπεζας Ωμέγα, για",
                "η Τράπεζα της Ελλάδος")) {
            assertEquals(List.of(), texts(text, SpanCategory.PRIVATE_COMPANY_NAME, SpanCategory.BANK_ACCOUNT), text);
        }
        assertEquals(List.of("GR6401401230000000123456789"), texts("Τράπεζα GR6401401230000000123456789",
                SpanCategory.BANK_ACCOUNT));
    }

    static TextUnit cell(String text, String header) {
        return new TextUnit("u0", "word/document.xml", UnitType.TABLE_CELL, text, text, List.of(),
                new TextUnit.TableCellLocation(0, 1, 0, header, false));
    }

    @Test
    void anAccountColumnProposesItsCellsAndABankColumnIsKept() {
        // A bank column's name is kept (owner policy), though its label still counts for header detection.
        assertEquals(List.of(), Detectors.detectTableSensitiveValues(cell("ΚΑΠΑ BANK", " ΠΙΣΤΩΤΙΚΟ  ΙΔΡΥΜΑ ")));
        assertEquals(List.of(), Detectors.detectTableSensitiveValues(cell("ΚΑΠΑ BANK", "Τράπεζα")));
        assertTrue(Detectors.isKnownColumnLabel("ΤΡΑΠΕΖΑ"));
        assertEquals("BANK_ACCOUNT:REDACT:0012345678", cellSpan(cell("0012345678", "ΑΡΙΘΜΟΣ ΛΟΓ/ΣΜΟΥ")));
        assertEquals("BANK_ACCOUNT:REDACT:0012345678", cellSpan(cell("0012345678", "IBAN")));
        // A column whose header merely mentions banking is not one.
        assertEquals(List.of(), Detectors.detectTableSensitiveValues(cell("1.687.225,93", "ΤΡΑΠΕΖΙΚΕΣ ΚΑΤΑΘΕΣΕΙΣ")));
    }

    static String cellSpan(TextUnit cell) {
        List<Span> spans = Detectors.detectTableSensitiveValues(cell);
        assertEquals(1, spans.size(), spans.toString());
        return spans.get(0).category().wire() + ":" + spans.get(0).action() + ":" + spans.get(0).text();
    }

    @Test
    void aCompanyNameIsTakenWhateverItsCueAndTheCueStays() {
        for (String cue : List.of("με επωνυμία", "με την επωνυμία", "υπό την επωνυμία", "με τον διακριτικό τίτλο",
                "και δ.τ.")) {
            assertEquals(List.of("ΑΛΦΑ ΒΗΤΑ ΕΜΠΟΡΙΚΗ Α.Ε."), texts("η εταιρεία " + cue + " ΑΛΦΑ ΒΗΤΑ ΕΜΠΟΡΙΚΗ Α.Ε. και",
                    SpanCategory.PRIVATE_COMPANY_NAME), cue);
        }
        // Several spaces and tabs inside the name, and a legal-form suffix, stay one name.
        assertEquals(List.of("ΓΑΜΑ  ΔΕΛΤΑ\tΣΥΜΒΟΥΛΕΥΤΙΚΗ ΕΤΑΙΡΙΑ ΠΕΡΙΟΡΙΣΜΕΝΗΣ ΕΥΘΥΝΗΣ"),
                texts("με την επωνυμία ΓΑΜΑ  ΔΕΛΤΑ\tΣΥΜΒΟΥΛΕΥΤΙΚΗ ΕΤΑΙΡΙΑ ΠΕΡΙΟΡΙΣΜΕΝΗΣ ΕΥΘΥΝΗΣ με ΑΦΜ",
                        SpanCategory.PRIVATE_COMPANY_NAME));
        assertEquals(List.of(), texts("έφερε ταμπέλα με την επωνυμία της εταιρείας", SpanCategory.PRIVATE_COMPANY_NAME));
    }

    @Test
    void aShapeHintInsideANamedRegionIsNotAskedSeparately() {
        String text = "για την εταιρεία με την επωνυμία ΑΛΦΑ ΒΗΤΑ ΓΑΜΑ ΔΕΛΤΑ ΕΠΕ με ΑΦΜ";
        Detectors.DetectionResult r = Detectors.detectAll(new DocumentData("d", List.of(unit(text)), List.of(),
                List.of()), RULES);
        assertTrue(r.reviewHints().stream().noneMatch(h -> h.detector().equals("greek_name_shape")
                || h.detector().equals("company_suffix")), r.reviewHints().toString());
        // Outside any such region, the same shape is still a question.
        Detectors.DetectionResult loose = Detectors.detectAll(new DocumentData("d", List.of(unit(
                "συναντήθηκε με τον ΑΛΦΑ ΒΗΤΑ")), List.of(), List.of()), RULES);
        assertTrue(loose.reviewHints().stream().anyMatch(h -> h.detector().equals("greek_name_shape")));
    }

    @Test
    void aStreetOrInstitutionInTheGenitiveIsNoPatronymic() {
        for (String text : List.of("στη δηλωμένη έδρα της επί της Ιεράς Οδού 101, Αθήνα",
                "με έδρα επί της Αγίας Σοφίας οδού αρ. 5", "που βρίσκεται επί της Μεγάλης Οδού 12",
                "το κατάστημα της Εθνικής Οδού 7")) {
            assertEquals(List.of(), texts(text, SpanCategory.FATHER_NAME), text);
        }
        // A real patronymic keeps every cue it had, a street one included when a name precedes it.
        assertEquals(List.of("του ΝΙΚΟΛΑΟΥ"), texts("ο ΠΑΠΑΔΟΠΟΥΛΟΣ ΓΕΩΡΓΙΟΣ του ΝΙΚΟΛΑΟΥ οδός Ερμού 5",
                SpanCategory.FATHER_NAME));
        assertEquals(List.of("του ΝΙΚΟΛΑΟΥ"), texts("ο ΠΑΠΑΔΟΠΟΥΛΟΣ του ΝΙΚΟΛΑΟΥ με ΑΦΜ " + TestDocx.validAfm("12345678"),
                SpanCategory.FATHER_NAME));
    }

    @Test
    void aBusinessSeatLeavesItsPrepositionVisible() {
        // The whole seat, its number and town included (it used to stop inside "αρ."); the "αρ." label in
        // it is a hard FIELD_LABEL, so it stays visible at the resolver.
        assertEquals(List.of("Ερμού αρ. 5 Αθήνα"), texts("με έδρα επί της Ερμού αρ. 5 Αθήνα", SpanCategory.BUSINESS_SEAT));
        assertEquals(List.of("Ερμού 5"), texts("με έδρα στην οδό Ερμού 5.", SpanCategory.BUSINESS_SEAT));
        assertEquals(List.of("Αθήνα"), texts("με έδρα την Αθήνα.", SpanCategory.BUSINESS_SEAT));
        assertEquals(List.of("Ερμού 5, Αθήνα"), texts("με έδρα στην οδό Ερμού 5, Αθήνα, και ΑΦΜ", SpanCategory.BUSINESS_SEAT));
        // A street-type word after the street's name is part of it (3127's shape).
        assertEquals(List.of("Ιερά οδού αρ. 101 Αθήνα"), texts("με έδρα επί της Ιερά οδού αρ. 101 Αθήνα, ως εταίρο",
                SpanCategory.BUSINESS_SEAT));
        // The seat is the place, never the clause or the next address part after it.
        assertEquals(List.of("Αθήνα"), texts("με έδρα την Αθήνα και εκπροσωπείται νόμιμα", SpanCategory.BUSINESS_SEAT));
        assertEquals(List.of("Αθήνα"), texts("με έδρα στην Αθήνα, οδός Ερμού αρ. 5", SpanCategory.BUSINESS_SEAT));
        assertEquals(List.of(), texts("με έδρα της εταιρείας", SpanCategory.BUSINESS_SEAT));
    }

    @Test
    void aBusinessSeatsNumberIsProposedAndItsLabelStaysVisible() {
        String text = "με έδρα επί της Ερμού αρ. 5 Αθήνα";
        assertEquals(List.of("5"), texts(text, SpanCategory.PRIVATE_ADDRESS));
        assertEquals(List.of("αρ."), texts(text, SpanCategory.FIELD_LABEL).stream().filter(t -> t.equals("αρ.")).toList());
        DocumentData doc = new DocumentData("d", List.of(unit(text)), List.of(), List.of());
        RedactionPlan plan = Resolver.resolveRedactions(doc, Detectors.detectAll(doc, RULES).resolverSpans(),
                FILES.policy());
        // The seat's spaces go with it; the hard label "αρ." is carved back out between the two runs.
        assertEquals(List.of("Ερμού ", " 5 Αθήνα"), plan.spans().stream().filter(s -> s.action() == SpanAction.REDACT)
                .map(Span::text).toList());
    }

    @Test
    void aGenericPartyRoleIsAHardPreservedLabelAndNeverAName() {
        for (String role : List.of("προσφεύγουσα εταιρία", "Προσφεύγουσα εταιρεία", "ελεγχόμενη επιχείρηση",
                "νόμιμος εκπρόσωπος", "προσφεύγων")) {
            Span span = only("κοινοποιήθηκαν στην " + role + " ηλεκτρονικά", SpanCategory.FIELD_LABEL);
            assertEquals(role, span.text());
            assertTrue(Resolver.isHardPreserve(span, FILES.policy()));
        }
        assertEquals(List.of(), texts("η Προσφεύγουσες ζητούν", SpanCategory.FIELD_LABEL)); // a closed class
    }

    @Test
    void theRegisterYearOfACompositeProtocolIsNoAuditOrder() {
        assertEquals(List.of(), texts("αρ. πρ. ΔΕΔ 123456 ΕΞ 2026 ΕΜΠ / 01-06-2026", SpanCategory.AUDIT_ORDER));
        assertEquals(List.of("12345"), texts("ΕΞ 12345", SpanCategory.AUDIT_ORDER));
    }

    @Test
    void theCourtSerialIsForPass2AndTheChamberIsPublicCourtStructure() {
        String text = "τη με αριθμό 512/2019 απόφαση του Διοικητικού Πρωτοδικείου Λαμίας (Τμήμα 2ο Μονομελές)";
        List<Span> refs = Detectors.detectCaseCourtReferences(unit(text));
        assertEquals(List.of("CASE_COURT_REFERENCE:512", "PUBLIC_SERVICE:2ο Μονομελές"), refs.stream()
                .map(s -> s.category().wire() + ":" + s.text()).toList());
        // Own case or precedent: a neutral question for pass 2, recommending neither.
        assertEquals(SpanAction.REVIEW, refs.get(0).action());
        assertFalse(Resolver.isHardPreserve(refs.get(0), FILES.policy()));
        assertTrue(Resolver.isHardPreserve(refs.get(1), FILES.policy()));
        for (String other : List.of("η υπ’ αρ. 512/2019 δικαστική απόφαση", "η υπ. αρ. 512/2019 απόφαση του",
                "της υπ' αριθμ. 512/2019 απόφασης")) {
            assertEquals(List.of("512"), Detectors.detectCaseCourtReferences(unit(other)).stream()
                    .filter(s -> s.category() == SpanCategory.CASE_COURT_REFERENCE).map(Span::text).toList(), other);
        }
        assertEquals(List.of("2ο"), Detectors.detectCaseCourtReferences(unit("(Τμήμα 2ο)")).stream()
                .map(Span::text).toList()); // the composition is optional
        assertTrue(texts(text, SpanCategory.PUBLIC_SERVICE).contains("Πρωτοδικείου Λαμίας"));
    }

    @Test
    void afmConfidenceFollowsChecksumAndLabel() {
        String valid = TestDocx.validAfm("12345678");
        String invalid = valid.substring(0, 8) + ((valid.charAt(8) - '0' + 1) % 10);
        List<Span> ok = Detectors.detectStructuredIds(unit("ΑΦΜ " + valid), RULES);
        assertEquals(1.0, ok.get(0).confidence());
        assertEquals(SpanCategory.AFM, ok.get(0).category());
        assertEquals(0.75, Detectors.detectStructuredIds(unit("ΑΦΜ: " + invalid), RULES).get(0).confidence());
        assertEquals(0.4, Detectors.detectStructuredIds(unit("αριθμός " + invalid), RULES).get(0).confidence());
    }

    @Test
    void publicEmailDomainIsPreserved() {
        List<Span> spans = Detectors.detectContacts(unit("info@aade.gr και x.y@example.com"), RULES);
        assertEquals(SpanAction.PRESERVE, spans.get(0).action());
        assertEquals(SpanAction.REDACT, spans.get(1).action());
    }

    @Test
    void phonesAreReviewHintsNotDecisions() {
        List<Span> spans = Detectors.detectContacts(unit("τηλ. 2101234567"), RULES);
        assertEquals(SpanAction.REVIEW, spans.get(0).action());
    }

    @Test
    void ibanChecksum() {
        assertTrue(DetectorSupport.ibanIsValid("GB82 WEST 1234 5698 7654 32"));
        assertFalse(DetectorSupport.ibanIsValid("GB82 WEST 1234 5698 7654 33"));
    }

    @Test
    void amkaBirthDate() {
        assertTrue(DetectorSupport.validAmkaBirthDate("01018512345", 2026));
        assertFalse(DetectorSupport.validAmkaBirthDate("32018512345", 2026));
    }

    @Test
    void detectAllSplitsReviewHintsFromResolverInput() {
        DocumentData doc = new DocumentData("d", List.of(unit("Ο Γεώργιος Παπαδόπουλος με ΑΦΜ " + TestDocx.validAfm("11111111"))),
                List.of(), List.of());
        Detectors.DetectionResult r = Detectors.detectAll(doc, RULES);
        assertTrue(r.reviewHints().stream().allMatch(s -> s.action() == SpanAction.REVIEW));
        assertTrue(r.resolverSpans().stream().noneMatch(s -> s.action() == SpanAction.REVIEW));
        assertTrue(r.resolverSpans().stream().anyMatch(s -> s.category() == SpanCategory.AFM));
    }

    // ------------------------------------------------------------------ hard-preserve phrase families

    /** The texts of the phrase-family spans {@code detectAll} gives one paragraph (optionally one family's). */
    static List<String> familyTexts(String paragraph, String... family) {
        return Detectors.detectAll(new DocumentData("d", List.of(unit(paragraph)), List.of(), List.of()), RULES)
                .resolverSpans().stream().filter(s -> s.detector().startsWith("phrase_family:"))
                .filter(s -> family.length == 0 || s.detector().equals("phrase_family:" + family[0]))
                .map(Span::text).toList();
    }

    @Test
    void everyPhraseFamilyIsAConfiguredHardPreserveCategory() {
        assertFalse(RULES.preserveFamilies().isEmpty());
        for (DetectorRules.PreserveFamily f : RULES.preserveFamilies()) {
            assertTrue(FILES.policy().hardPreserveCategories().contains(f.category().wire()), f.name());
        }
        Span kept = Detectors.detectAll(new DocumentData("d", List.of(unit("της Φορολογικής Διοίκησης")), List.of(),
                List.of()), RULES).resolverSpans().stream().filter(s -> s.detector().startsWith("phrase_family:"))
                .findFirst().orElseThrow();
        assertTrue(Resolver.isHardPreserve(kept, FILES.policy()));
        assertEquals(SpanOrigin.DETERMINISTIC, kept.origin());
    }

    @Test
    void aFamilyMatchesCaseAccentsFinalSigmaAndInflectionAsWholeWords() {
        for (String text : List.of("Φορολογική Διοίκηση", "ΦΟΡΟΛΟΓΙΚΗ ΔΙΟΙΚΗΣΗ", "της φορολογικής διοίκησης",
                "Φορολογικης Διοικησης")) {
            assertEquals(List.of(text.replace("της ", "")), familyTexts(text, "public_bodies"), text);
        }
        // A decomposed accent (a letter, then its combining mark) is the same word, at the same offsets.
        String decomposed = "Φορολογικη\u0301 Διοι\u0301κηση";
        assertEquals(List.of(decomposed), familyTexts(decomposed, "public_bodies"));
        // Whole words only: never inside a longer word.
        assertEquals(List.of(), familyTexts("Υπερφορολογική Διοικησηδες", "public_bodies"));
        // A tab or a few spaces between the words still match; a phrase never runs across a sentence.
        assertEquals(List.of("ΔΙΕΥΘΥΝΣΗ ΕΠΙΛΥΣΗΣ\tΔΙΑΦΟΡΩΝ"), familyTexts("ΔΙΕΥΘΥΝΣΗ ΕΠΙΛΥΣΗΣ\tΔΙΑΦΟΡΩΝ", "ded_units"));
    }

    @Test
    void aFamilyKeepsTheRoleOrTheLabelAndNeverTheNameAfterIt() {
        assertEquals(List.of("Τοπογράφου Μηχανικού"), familyTexts("του Τοπογράφου Μηχανικού Λεωνίδα Ιωαννίδη",
                "party_roles"));
        assertEquals(List.of("Διευθύνων Σύμβουλος"), familyTexts("ο Διευθύνων Σύμβουλος Νίκος Παππάς", "party_roles"));
        assertEquals(List.of("ο διαχειριστής", "της εταιρείας"), familyTexts("ο διαχειριστής της εταιρείας",
                "party_roles"));
        assertEquals(List.of("η εταιρεία"), familyTexts("η εταιρεία ΚΑΠΑ ΛΑΜΔΑ Α.Ε.", "party_roles"));
        // The company's name itself is still proposed for redaction by its cue rule.
        assertEquals(List.of("ΚΑΠΑ ΛΑΜΔΑ Α.Ε."), texts("η εταιρεία ΚΑΠΑ ΛΑΜΔΑ Α.Ε.", SpanCategory.PRIVATE_COMPANY_NAME));
    }

    @Test
    void aLabelOnlyFamilyKeepsTheWordOnlyWhereItStandsAsALabel() {
        assertEquals(List.of("Τράπεζα"), familyTexts("Τράπεζα", "identity_labels")); // a header cell
        assertEquals(List.of("Τράπεζα"), familyTexts("Τράπεζα: ΑΛΦΑ", "identity_labels")); // a label and its value
        assertEquals(List.of("ΤΡΑΠΕΖΑ"), familyTexts("1. ΤΡΑΠΕΖΑ", "identity_labels")); // a numbered heading
        assertEquals(List.of(), familyTexts("στην Τράπεζα Πειραιώς", "identity_labels")); // part of a bank's name
        assertEquals(List.of(), familyTexts("Ο ΙΒΑΝ ΠΕΤΡΟΦ", "identity_labels")); // a first name, not a label
    }

    @Test
    void aFragmentIsKeptOnlyInsideItsCompleteVerifiedExpression() {
        assertEquals(List.of("Συνολικό Δηλωθέν Εισόδημα"), familyTexts("Συνολικό Δηλωθέν Εισόδημα"));
        assertEquals(List.of(), familyTexts("Συνολικό Δηλωθέν"));
        assertEquals(List.of("Περιγραφή Φορολογητέου Εισοδήματος"), familyTexts("Περιγραφή Φορολογητέου Εισοδήματος"));
        assertEquals(List.of(), familyTexts("Περιγραφή Φορολογητέου"));
        assertEquals(List.of("ΣΤΟΧΟΘΕΣΙΑ ΕΜΜΕΣΩΝ ΤΕΧΝΙΚΩΝ ΣΕ ΜΗ ΕΠΙΤΗΔΕΥΜΑΤΙΕΣ"),
                familyTexts("ΣΤΟΧΟΘΕΣΙΑ ΕΜΜΕΣΩΝ ΤΕΧΝΙΚΩΝ ΣΕ ΜΗ ΕΠΙΤΗΔΕΥΜΑΤΙΕΣ ΦΟΡ. ΕΤΟΥΣ 2021", "section_headings"));
        assertEquals(List.of(), familyTexts("ΤΕΧΝΙΚΩΝ ΣΕ", "section_headings"));
        assertEquals(List.of("ΕΝΑΛΛΑΚΤΙΚΟΣ ΤΡΟΠΟΣ ΥΠΟΛΟΓΙΣΜΟΥ ΤΗΣ ΕΛΑΧΙΣΤΗΣ ΦΟΡΟΛΟΓΙΑΣ"),
                familyTexts("«ΕΝΑΛΛΑΚΤΙΚΟΣ ΤΡΟΠΟΣ ΥΠΟΛΟΓΙΣΜΟΥ ΤΗΣ ΕΛΑΧΙΣΤΗΣ ΦΟΡΟΛΟΓΙΑΣ»", "section_headings"));
        assertEquals(List.of(), familyTexts("ΥΠΟΛΟΓΙΣΜΟΥ ΤΗΣ", "section_headings"));
        assertEquals(List.of("Διαθέσιμα περιουσιακά στοιχεία"), familyTexts("Διαθέσιμα περιουσιακά στοιχεία κατά την",
                "section_headings"));
        assertEquals(List.of(), familyTexts("Διαθέσιμα Περιουσιακά", "section_headings"));
        assertEquals(List.of("Μεθοδολογία Έμμεσων τεχνικών Ελέγχου"),
                familyTexts("«Μεθοδολογία Έμμεσων τεχνικών Ελέγχου»", "section_headings"));
        assertEquals(List.of("Ο ΠΡΟΪΣΤΑΜΕΝΟΣ ΤΗΣ ΔΙΕΥΘΥΝΣΗΣ ΕΠΙΛΥΣΗΣ ΔΙΑΦΟΡΩΝ"),
                familyTexts("Ο ΠΡΟΪΣΤΑΜΕΝΟΣ ΤΗΣ ΔΙΕΥΘΥΝΣΗΣ ΕΠΙΛΥΣΗΣ ΔΙΑΦΟΡΩΝ", "official_headings"));
    }

    @Test
    void aCompositeReferenceKeepsItsFixedPartsAndLeavesTheSerial() {
        assertEquals(List.of("ΕΛ.ΚΕ.1 ΑΤ", "ΕΞ2024"),
                familyTexts("η υπ. αριθμ. ΕΛ.ΚΕ.1 ΑΤ 1054853 ΕΞ2024 Πρόσκληση", "register_references"));
        // The register year and its date with a letter O typed for a zero; the serial before it is not kept.
        assertEquals(List.of("ΕΞ 2Ο26 ΕΜΠ / 1Ο-06-2Ο26"),
                familyTexts("Το με αρ. πρ. ΔΕΔ 490154 ΕΞ 2Ο26 ΕΜΠ / 1Ο-06-2Ο26 έγγραφο", "register_references"));
        assertEquals(List.of("ΕΙ 2024 ΕΜΠ/26.Ο7.2024"), familyTexts("ΕΛ.ΚΕ. 1 ΑΤ 188845 ΕΙ 2024 ΕΜΠ/26.Ο7.2024 υπόμνημα",
                "register_references").stream().filter(t -> t.startsWith("ΕΙ")).toList());
        // "ΔΑ" is kept only in a sender's protocol reference, never as an invoice's code.
        assertEquals(List.of("αρ. πρ. αποστολέα ΔΑ", "/23-06-2026"),
                familyTexts("Το με αρ. πρ. αποστολέα ΔΑ 1136/23-06-2026 μήνυμα", "register_references"));
        assertEquals(List.of(), familyTexts("ΔΑ 1136/23-06-2026", "register_references"));
        // No number is ever kept for its value.
        String axk = "(Α.Χ.Κ. 76/141)";
        assertTrue(familyTexts(axk).stream().noneMatch(t -> t.contains("141")), familyTexts(axk).toString());
        String atb = "βεβαιώθηκε ως ΑΤΒ 25761/10.09.2024.";
        assertEquals(List.of("ΑΤΒ"), familyTexts(atb).stream().filter(t -> t.contains("ΑΤΒ") || t.contains("25761"))
                .toList());
        // The ΑΤΒ number is a taxpayer-file number (owner policy): its digits are proposed, prefix and date stay.
        assertEquals(List.of("25761"), texts(atb, SpanCategory.CASE_REF_NUMBER));
        assertEquals(List.of("48213"), texts("ΑΤΒ: 48213 της Δ.Ο.Υ.", SpanCategory.CASE_REF_NUMBER));
        assertEquals(List.of(), texts("ΑΤΒΓΔ 48213 και ΚΑΤΒ 4", SpanCategory.CASE_REF_NUMBER)); // inside a word: none
        String poa = "σύμφωνα με το υπ. αρ. 2.701/2007 Πληρεξούσιο.";
        assertTrue(familyTexts(poa).contains("Πληρεξούσιο"));
        assertTrue(familyTexts(poa).stream().noneMatch(t -> t.contains("2.701")), familyTexts(poa).toString());
    }

    /** A cell joins its paragraphs with nothing; a family reads a paragraph break there as a line break. */
    @Test
    void aFamilyReadsACellsParagraphBreakAsALineBreakAtTheCellsOwnOffsets() {
        TextUnit cell = paragraphs("u0", UnitType.TABLE_CELL, new TextUnit.TableCellLocation(0, 0, 0, "", true),
                "/0/9/1/1", "Αυτοτελούς Τμήματος", "Διοικητικής Υποστήριξης");
        assertEquals("Αυτοτελούς ΤμήματοςΔιοικητικής Υποστήριξης", cell.normalizedText());
        List<Span> kept = Detectors.detectAll(new DocumentData("d", List.of(cell), List.of(), List.of()), RULES)
                .resolverSpans().stream().filter(s -> s.detector().equals("phrase_family:ded_units")).toList();
        assertEquals(List.of("Αυτοτελούς ΤμήματοςΔιοικητικής Υποστήριξης"), kept.stream().map(Span::text).toList());
        assertEquals(0, kept.getFirst().start());
        assertEquals(cell.normalizedText().length(), kept.getFirst().end());
    }

    @Test
    void aMalformedFamilyStopsTheServiceStarting(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        for (String name : List.of("policy.yaml", "prompt_injection.yaml")) {
            java.nio.file.Files.copy(Path.of("config", name), dir.resolve(name));
        }
        // Malformed structure is refused whatever the category, a wrong or unknown one included.
        for (String[] bad : List.of(new String[] {"FIELD_LABEL", "'Φορολογική'"}, new String[] {"FIELD_LABEL", "'(α)(β)'"},
                new String[] {"FIELD_LABEL", "'(?i)αβ'"}, new String[] {"DATE", "'(α)(β)'"},
                new String[] {"NOT_A_CATEGORY", "'(?i)αβ'"})) {
            java.nio.file.Files.writeString(dir.resolve("regex_patterns.yaml"), "preserve_families:\n  x:\n    category: "
                    + bad[0] + "\n    scope: any\n    patterns:\n      - " + bad[1] + "\n");
            assertTrue(org.junit.jupiter.api.Assertions.assertThrows(ConfigurationError.class,
                    () -> Config.loadFileConfig(dir)).getMessage().contains("preserve family"), bad[1]);
        }
        java.nio.file.Files.writeString(dir.resolve("regex_patterns.yaml"),
                "preserve_families:\n  x:\n    category: DATE\n    scope: other\n    patterns:\n      - 'ημερα'\n");
        assertTrue(org.junit.jupiter.api.Assertions.assertThrows(ConfigurationError.class,
                () -> Config.loadFileConfig(dir)).getMessage().contains("scope must be"));
    }

    /**
     * A family whose category is not a hard-preserve category, or no category at all, is disabled
     * with a warning: the service starts, the other families work, and the disabled one produces
     * nothing (it is neither hard-preserved nor kept as an ordinary PRESERVE).
     */
    @Test
    void aFamilyWithAWrongCategoryIsDisabledAndTheRestStillWork(@org.junit.jupiter.api.io.TempDir Path dir)
            throws Exception {
        for (String name : List.of("policy.yaml", "prompt_injection.yaml")) {
            java.nio.file.Files.copy(Path.of("config", name), dir.resolve(name));
        }
        java.nio.file.Files.writeString(dir.resolve("regex_patterns.yaml"), "preserve_families:\n"
                + "  misfiled:\n    category: DATE\n    scope: any\n    patterns:\n      - 'γενικα στοιχεια'\n"
                + "      - 'αριθμοσ (\\d+) πραξησ'\n"
                + "  unknown:\n    category: PUBLIK_SERVICE\n    scope: any\n    patterns:\n      - 'πηγεσ κεφαλαιων'\n"
                + "  missing:\n    scope: any\n    patterns:\n      - 'τελικο συμπερασμα'\n"
                + "  kept:\n    category: FIELD_LABEL\n    scope: any\n    patterns:\n      - 'ορισμοι οροι'\n");
        FileConfig files = Config.loadFileConfig(dir);
        assertEquals(List.of("kept"), files.rules().preserveFamilies().stream()
                .map(DetectorRules.PreserveFamily::name).toList());
        // The policy is what the file says: nothing was promoted to hard preserve on the family's behalf.
        assertFalse(files.policy().hardPreserveCategories().contains("DATE"));
        TextUnit unit = unit("Γενικά Στοιχεία, αριθμός 12 πράξης, Πηγές Κεφαλαίων, Τελικό συμπέρασμα, Ορισμοί όροι");
        List<Span> spans = Detectors.detectAll(new DocumentData("d", List.of(unit), List.of(), List.of()),
                files.rules()).resolverSpans().stream().filter(s -> s.detector().startsWith("phrase_family:")).toList();
        assertEquals(List.of("phrase_family:kept:Ορισμοί όροι"), spans.stream()
                .map(s -> s.detector() + ":" + s.text()).toList());
    }

    // ------------------------------------------------------------------ the official signatory

    /** A unit whose characters come from {@code paragraphs}, each its own paragraph under {@code path}. */
    static TextUnit paragraphs(String id, UnitType type, TextUnit.Location location, String path, String... paragraphs) {
        StringBuilder text = new StringBuilder();
        List<XmlCharRef> map = new java.util.ArrayList<>();
        for (int p = 0; p < paragraphs.length; p++) {
            int[] cps = paragraphs[p].codePoints().toArray();
            for (int i = 0; i < cps.length; i++) {
                text.appendCodePoint(cps[i]);
                map.add(new XmlCharRef("word/document.xml", path + "/" + p + "/0/0", i));
            }
        }
        return new TextUnit(id, "word/document.xml", type, text.toString(), text.toString(), map, location);
    }

    /** A decision of {@code bodyParagraphs} filler paragraphs, then {@code end}: the units of its last part. */
    static DocumentData decision(int bodyParagraphs, TextUnit... end) {
        List<TextUnit> units = new java.util.ArrayList<>();
        for (int i = 0; i < bodyParagraphs; i++) {
            units.add(paragraphs("p" + i, UnitType.PARAGRAPH, new TextUnit.ParagraphLocation(i), "/0/" + i,
                    "Επειδή η προσφυγή εξετάστηκε."));
        }
        units.addAll(List.of(end));
        return new DocumentData("d", units, List.of(), List.of());
    }

    static TextUnit signatureCell(String id, int row, int col, String... paragraphs) {
        return paragraphs(id, UnitType.TABLE_CELL, new TextUnit.TableCellLocation(0, row, col, "", row == 0),
                "/0/50/" + (row + 1) + "/" + (col + 1), paragraphs);
    }

    static List<Span> signatories(DocumentData doc) {
        return Detectors.detectAll(doc, RULES).resolverSpans().stream()
                .filter(s -> s.category() == SpanCategory.OFFICIAL_SIGNATORY).toList();
    }

    @Test
    void theSignatoryInATableCellIsAHardPreserveOfTheNameOnly() {
        TextUnit cell = signatureCell("c1", 1, 1, "Η Προϊστάμενη της", "Υποδιεύθυνσης Επανεξέτασης", "", "ΣΚΟΥΡΑ  ΓΡΑΜΜΑΤΩ");
        List<Span> found = signatories(decision(10, cell));
        assertEquals(List.of("ΣΚΟΥΡΑ  ΓΡΑΜΜΑΤΩ"), found.stream().map(Span::text).toList());
        assertEquals(cell.normalizedText().indexOf("ΣΚΟΥΡΑ"), found.getFirst().start()); // the title is not covered
        assertTrue(Resolver.isHardPreserve(found.getFirst(), FILES.policy()));
        // The name is the one shaped like a name after the title's own lines (its unit, its code).
        TextUnit coded = signatureCell("c2", 1, 1, "Η Προϊστάμενη του", "Τμήματος Επανεξέτασης Α4", "", "ΕΥΑΓΓΕΛΙΑ ΤΕΡΖΑΚΟΥ");
        assertEquals(List.of("ΕΥΑΓΓΕΛΙΑ ΤΕΡΖΑΚΟΥ"), signatories(decision(10, coded)).stream().map(Span::text).toList());
    }

    @Test
    void theSignatoryMayStandInTheCellBelowItsTitleOrInAParagraph() {
        TextUnit title = signatureCell("c1", 0, 1, "ΜΕ ΕΝΤΟΛΗ ΤΟΥ ΠΡΟΪΣΤΑΜΕΝΟΥ", "ΤΗΣ Δ/ΝΣΗΣ ΕΠΙΛΥΣΗΣ ΔΙΑΦΟΡΩΝ");
        TextUnit name = signatureCell("c2", 1, 1, "Η ΠΡΟΪΣΤΑΜΕΝΗ ΤΗΣ ΥΠΟΔΙΕΥΘΥΝΣΗΣ ΕΠΑΝΕΞΕΤΑΣΗΣ ", "", "ΓΡΑΜΜΑΤΩ ΣΚΟΥΡΑ");
        assertEquals(List.of("ΓΡΑΜΜΑΤΩ ΣΚΟΥΡΑ"), signatories(decision(10, title, name)).stream().map(Span::text).toList());
        TextUnit paragraphTitle = paragraphs("t", UnitType.PARAGRAPH, new TextUnit.ParagraphLocation(10), "/0/40",
                "Ο ΠΡΟΪΣΤΑΜΕΝΟΣ ΤΗΣ ΔΙΕΥΘΥΝΣΗΣ");
        TextUnit paragraphName = paragraphs("n", UnitType.PARAGRAPH, new TextUnit.ParagraphLocation(11), "/0/41",
                "ΙΩΑΝΝΗΣ ΠΑΠΑΣ");
        assertEquals(List.of("ΙΩΑΝΝΗΣ ΠΑΠΑΣ"), signatories(decision(10, paragraphTitle, paragraphName)).stream()
                .map(Span::text).toList());
    }

    @Test
    void aSignatoryIsOnlyEverPositivelyIdentified() {
        // A name in mixed case needs one of its words in the name lists.
        assertEquals(List.of("Ευαγγελία Τερζάκου"), signatories(decision(10, signatureCell("c", 1, 1, "Η Προϊστάμενη",
                "Ευαγγελία Τερζάκου"))).stream().map(Span::text).toList());
        assertEquals(List.of(), signatories(decision(10, signatureCell("c", 1, 1, "Η Προϊστάμενη", "Ζυλφίκ Κραντάρ"))));
        // No signing title: no signatory, whatever the shape.
        assertEquals(List.of(), signatories(decision(10, signatureCell("c", 1, 1, "Ο ελεγκτής", "ΓΡΑΜΜΑΤΩ ΣΚΟΥΡΑ"))));
        // A private party in the block: skipped.
        assertEquals(List.of(), signatories(decision(10, signatureCell("c", 1, 1, "Ο Προϊστάμενος", "του προσφεύγοντος",
                "ΓΡΑΜΜΑΤΩ ΣΚΟΥΡΑ"))));
        // Not at the end of the document: not a final signature block.
        TextUnit early = paragraphs("e0", UnitType.PARAGRAPH, new TextUnit.ParagraphLocation(0), "/0/0",
                "Ο ΠΡΟΪΣΤΑΜΕΝΟΣ ΤΗΣ ΔΙΕΥΘΥΝΣΗΣ");
        TextUnit earlyName = paragraphs("e1", UnitType.PARAGRAPH, new TextUnit.ParagraphLocation(1), "/0/1",
                "ΙΩΑΝΝΗΣ ΠΑΠΑΣ");
        List<TextUnit> units = new java.util.ArrayList<>(List.of(early, earlyName));
        units.addAll(decision(20).textUnits().stream().map(u -> paragraphs(u.unitId(), UnitType.PARAGRAPH,
                u.location(), "/0/" + (5 + Integer.parseInt(u.unitId().substring(1))), u.normalizedText())).toList());
        assertEquals(List.of(), signatories(new DocumentData("d", units, List.of(), List.of())));
    }

    // ------------------------------------------------------------------ the name lists, as positive evidence

    static List<Span> listed(String paragraph) {
        return Detectors.detectAll(new DocumentData("d", List.of(unit(paragraph)), List.of(), List.of()), RULES)
                .resolverSpans().stream().filter(s -> s.detector().equals(Detectors.LISTED_NAME_DETECTOR)).toList();
    }

    @Test
    void aGivenNameAndASurnameSideBySideAreAnOrdinaryRedactProposal() {
        List<Span> found = listed("του Τοπογράφου Μηχανικού Λεωνίδα Ιωαννίδη.");
        assertEquals(List.of("Λεωνίδα Ιωαννίδη"), found.stream().map(Span::text).toList());
        Span s = found.getFirst();
        assertEquals(SpanAction.REDACT, s.action());
        assertFalse(Resolver.isHardRedact(s, FILES.policy())); // evidence for the LLM passes, never a decision
        assertEquals(List.of("ΜΙΧΟΣ ΝΙΚΟΛΑΟΣ"), listed("Ονοματεπώνυμο ΜΙΧΟΣ ΝΙΚΟΛΑΟΣ").stream().map(Span::text).toList());
        // The shape hint over the same two words is the weaker copy of that proposal, and is dropped.
        Detectors.DetectionResult r = Detectors.detectAll(new DocumentData("d", List.of(unit("ο Λεωνίδα Ιωαννίδη")),
                List.of(), List.of()), RULES);
        assertTrue(r.reviewHints().stream().noneMatch(h -> h.text().equals("Λεωνίδα Ιωαννίδη")));
    }

    @Test
    void anUnlistedNeighbourIsANameOnlyNextToAListedGivenNameInAPrivatePartyContext() {
        assertEquals(List.of("Νικόλαος Ζυλφίκ"), listed("του προσφεύγοντος Νικόλαος Ζυλφίκ").stream().map(Span::text)
                .toList());
        assertEquals(List.of(), listed("ο Νικόλαος Ζυλφίκ υπέγραψε"));
        // A surname beside an unlisted word is no evidence of a full name ("ΕΘΝΙΚΗ" is a bank's word).
        assertEquals(List.of(), listed("λογαριασμού ΕΘΝΙΚΗ ΜΙΧΟΣ"));
        // Absence from the lists keeps nothing: the unlisted pair is still a REVIEW hint for the LLM passes.
        Detectors.DetectionResult r = Detectors.detectAll(new DocumentData("d", List.of(unit("ο Ζυλφίκ Κραντάρ")),
                List.of(), List.of()), RULES);
        assertTrue(r.reviewHints().stream().anyMatch(h -> h.text().equals("Ζυλφίκ Κραντάρ")));
    }

    @Test
    void theNameListsNeverProposeTheSignatoryOrAnythingInsideAKeptPhrase() {
        TextUnit cell = signatureCell("c1", 1, 1, "Ο Προϊστάμενος", "ΓΕΩΡΓΙΟΣ ΠΑΠΑΔΟΠΟΥΛΟΣ");
        Detectors.DetectionResult r = Detectors.detectAll(decision(10, cell), RULES);
        assertTrue(r.resolverSpans().stream().anyMatch(s -> s.category() == SpanCategory.OFFICIAL_SIGNATORY));
        assertTrue(r.resolverSpans().stream().noneMatch(s -> s.detector().equals(Detectors.LISTED_NAME_DETECTOR)
                && s.unitId().equals("c1")));
    }

    // ------------------------------------------------------------------ hard preserves never reach a private value

    /** Whether any character of the first occurrence of {@code part} lies inside a hard preserve. */
    static boolean anyHardPreserved(String paragraph, String part) {
        int at = paragraph.indexOf(part);
        assertTrue(at >= 0, part);
        return Detectors.detectAll(new DocumentData("d", List.of(unit(paragraph)), List.of(), List.of()), RULES)
                .resolverSpans().stream().filter(s -> Resolver.isHardPreserve(s, FILES.policy()))
                .anyMatch(s -> s.start() < at + part.length() && at < s.end());
    }

    @Test
    void aSerialShapedLikeAPublishedReferenceIsNeverHardPreservedOnItsShapeAlone() {
        // A hard preserve outranks every REDACT either LLM pass can return, so a rule that keeps a private
        // serial on its shape alone exposes it for good. An ΑΑΔΕ decision number's shape ("Α.1165/2022")
        // is also a protocol's, and a law's "ν. 1234/2021" must start a word, not end one ("των").
        assertFalse(anyHardPreserved("Το με αρ. πρωτ. Α.1234/2021 έγγραφο της Δ.Ο.Υ.", "1234"));
        assertFalse(anyHardPreserved("σχετικό το ΔΕΔΑ.123/2021 έγγραφο", "123/2021"));
        assertFalse(anyHardPreserved("με την α.4321/2020 πράξη του ελέγχου", "4321"));
        assertFalse(anyHardPreserved("οι αιτήσεις των 5678/2021 και 5679/2021 απορρίφθηκαν", "5678"));
    }

    @Test
    void anAadeDecisionOrCircularIsAPublishedReferenceOnlyWithItsPublishedActCue() {
        for (String[] c : new String[][] {
                {"Της με αριθμό Α.1165/22.11.2022 απόφασης του Διοικητή της ΑΑΔΕ (ΦΕΚ Β΄ 6009)", "Α.1165/22.11.2022"},
                {"Επειδή σύμφωνα με την Α.1082/2021 με θέμα «Περιπτώσεις έλλειψης υπαιτιότητας»", "Α.1082/2021"},
                {"σύμφωνα με τις διατάξεις της εγκυκλίου Ε.2015/2020 με θέμα “Οδηγίες”", "Ε.2015/2020"},
                {"σύμφωνα με την Ε.2128/2020 εγκύκλιο Διοικητή ΑΑΔΕ", "Ε.2128/2020"},
                {"σύμφωνα με την Ε. 2173/2020 με θέμα «Αλληλέγγυα ευθύνη»", "Ε. 2173/2020"}}) {
            assertTrue(texts(c[0], SpanCategory.LEGAL_REF).contains(c[1]), c[0]);
            // A published administrative instrument, never a court decision.
            assertEquals(List.of(), texts(c[0], SpanCategory.COURT_DECISION), c[0]);
        }
        // No published-act cue: the model decides (a hard tier needs evidence, not a shape).
        assertFalse(anyHardPreserved("με την Ε. 2128/2020, η οποία εκδόθηκε κατόπιν", "2128"));
        assertFalse(anyHardPreserved("Το με αρ. πρωτ. Α.1234/2021 απόφαση του Διοικητή", "1234"));
    }

    // ------------------------------------------------------------------ settled deterministically: never a pass-2 question

    /** The texts the rules hard-preserve in one paragraph. */
    static List<String> hardKept(String paragraph) {
        return hardKeptIn(new DocumentData("d", List.of(unit(paragraph)), List.of(), List.of()));
    }

    static List<String> hardKeptIn(DocumentData document) {
        return Detectors.detectAll(document, RULES).resolverSpans().stream()
                .filter(s -> Resolver.isHardPreserve(s, FILES.policy())).map(Span::text).toList();
    }

    @Test
    void aPublishedInstrumentIsKeptWholeOnlyWithEvidenceOfItsPublication() {
        assertTrue(hardKept("β. Του άρθρου 10 της Δ. ΟΡΓ. Α 1125859 ΕΞ 2020/23.10.2020 Απόφασης του Διοικητή της ΑΑΔΕ")
                .contains("Δ. ΟΡΓ. Α 1125859 ΕΞ 2020/23.10.2020"));
        assertTrue(hardKept("Την Δ.Ε.Δ. 1126366 ΕΞ 2016/30.08.2016 (ΦΕΚ Β΄2759/1.9.2016) Απόφαση του Προϊσταμένου")
                .contains("Δ.Ε.Δ. 1126366 ΕΞ 2016/30.08.2016"));
        assertTrue(hardKept("«Με την απόφαση ΔΕΣ Α 1077357 ΕΞ 10.5.2013, όπως δημοσιεύθηκε στα ΦΕΚ")
                .contains("ΔΕΣ Α 1077357 ΕΞ 10.5.2013"));
        assertTrue(hardKept("της υπ' αριθ. ΔΕΣ Α. 1077357 ΕΞ. 10/5/2013 (ΦΕΚ Β 1136) Α.Υ.Ο.")
                .contains("ΔΕΣ Α. 1077357 ΕΞ. 10/5/2013"));
        // The same shape with no evidence of publication is a protocol of the file: its serial is never kept.
        assertFalse(anyHardPreserved("Το με αρ. πρ. ΔΕΔ 490154 ΕΞ 2Ο26 ΕΜΠ / 1Ο-06-2Ο26 έγγραφο", "490154"));
        assertFalse(anyHardPreserved("η ΔΕΔ 1126366 ΕΞ 2016/30.08.2016 κοινοποιήθηκε στον προσφεύγοντα", "1126366"));
        // A number is never kept for its digits: the same serial alone is no reference.
        assertFalse(anyHardPreserved("σύμφωνα με το 1126366 του φακέλου", "1126366"));
    }

    @Test
    void lawCircularGazetteAndArticleReferencesAreKeptWhole() {
        List<String> kept = hardKept("β. Του άρθρου 72 του Ν. 5104/2024 (ΦΕΚ Α’ 58), του ν.51Ο4/2Ο24, της ΠΟΛ 1064/12.04.2017,"
                + " της ΠΟΛ.1259/22-12-2014, στα ΦΕΚ. 1136/Β/10-5-2013 και ΦΕΚ 2759/ τ. Β’/ 01.09.2016");
        for (String ref : List.of("άρθρου 72", "Ν. 5104/2024", "ΦΕΚ Α’ 58", "ν.51Ο4/2Ο24", "ΠΟΛ 1064/12.04.2017",
                "ΠΟΛ.1259/22-12-2014", "ΦΕΚ. 1136/Β/10-5-2013", "ΦΕΚ 2759/ τ. Β’/ 01.09.2016")) {
            assertTrue(kept.contains(ref), ref + " / " + kept);
        }
        assertEquals(List.of("άρθρου 21§4", "άρθρα 31 και 32", "παρ. 1 του άρθρου 33", "ΑΡΘΡΟ 2", "αρθ. 34"),
                texts("κατά το άρθρου 21§4, τα άρθρα 31 και 32, παρ. 1 του άρθρου 33, ΑΡΘΡΟ 2 και αρθ. 34",
                        SpanCategory.ARTICLE_REF));
        // A street number, a bare number, an OCR Ο outside a citation, a company-statute gazette issue, and an
        // article list next to a case serial: none of them is kept.
        assertEquals(List.of(), texts("οδός Ερμού αρ. 5, και ο αριθμός 28", SpanCategory.ARTICLE_REF));
        assertFalse(anyHardPreserved("ΑΦΜ 12Ο456789 του προσφεύγοντος", "12Ο456789"));
        assertFalse(anyHardPreserved("το καταστατικό σε Φ.Ε.Κ. με αριθμό φύλλου 4321", "4321"));
        assertFalse(anyHardPreserved("κατά τα άρθρα 5 και 52/2026 πράξη", "52/2026"));
    }

    @Test
    void councilOfStatePrecedentIsKeptButAnOwnCaseDecisionIsNot() {
        assertTrue(hardKept("(πρβλ. ΣτΕ 453/2011, 73/2001, 250/1996, 1262/1991), δεν επάγεται")
                .contains("ΣτΕ 453/2011, 73/2001, 250/1996, 1262/1991"));
        assertTrue(hardKept("έχει κριθεί νομολογιακά με την υπ’ αριθ. 1014/29-05-2019 απόφαση του ΣτΕ ότι")
                .contains("1014/29-05-2019"));
        // No precedent cue: the appellant's own decision stays the pass-2 question it was.
        assertFalse(anyHardPreserved("σε συμμόρφωση προς την υπ’ αριθ. 231/2020 απόφαση του ΣτΕ", "231"));
        assertFalse(anyHardPreserved("τη με αριθμό 231/2020 απόφαση του Διοικητικού Πρωτοδικείου", "231"));
    }

    @Test
    void fiscalPeriodsAmountsAndPercentagesAreKeptButNeverInsideAnIdentifier() {
        List<String> kept = hardKept("ΧΡΗΣΗ 2021, ΦΟΡΟΛΟΓΙΚΟ ΕΤΟΣ 2019, φορολογικού έτους 2021, για το διάστημα "
                + "01/01-31/12/2021 και 1/1/2003 έως την 31/12/2010, ποσό 7.755,82 και -199.414,33 και 449.115,17 ευρώ"
                + " και 5.000 € και 10,501.68, τριάντα τρία τοις εκατό (33%) και 75%");
        for (String v : List.of("ΧΡΗΣΗ 2021", "ΦΟΡΟΛΟΓΙΚΟ ΕΤΟΣ 2019", "φορολογικού έτους 2021", "01/01-31/12/2021",
                "1/1/2003 έως την 31/12/2010", "7.755,82", "-199.414,33", "449.115,17 ευρώ", "5.000 €", "10,501.68",
                "τριάντα τρία τοις εκατό (33%)", "75%")) {
            assertTrue(kept.contains(v), v + " / " + kept);
        }
        // One date is never a period (it may be a date of birth); a rate and a year list are not money.
        assertEquals(List.of(), texts("Ημερομηνία γέννησης 01/02/1980", SpanCategory.FISCAL_PERIOD, SpanCategory.TAX_YEAR));
        assertFalse(anyHardPreserved("με συντελεστή 0,0037 επί της αξίας", "0,0037"));
        assertFalse(anyHardPreserved("για τα έτη 2019,2020 και", "2019,2020"));
        // Digits shaped like an amount, a date or a law inside an identifier stay the identifier's; the hard
        // redactions still win.
        String afm = TestDocx.validAfm("12345678");
        String iban = TestDocx.validGreekIban("01101230000012345678901");
        String ids = "ΑΦΜ " + afm + ", IBAN " + iban + ", ΑΤΑΚ 01234567890, αρ. πρωτ. 34519/30-03-2026, ποσό 1.250,00";
        for (String id : List.of(afm, iban, "01234567890", "34519")) {
            assertFalse(anyHardPreserved(ids, id), id);
        }
        List<Span> spans = Detectors.detectAll(new DocumentData("d", List.of(unit(ids)), List.of(), List.of()), RULES)
                .resolverSpans();
        for (String id : List.of(afm, iban, "01234567890")) {
            assertTrue(spans.stream().anyMatch(s -> s.text().equals(id) && Resolver.isHardRedact(s, FILES.policy())), id);
        }
    }

    @Test
    void headingsAndTermsOfTheSourceDecisionsAreKeptButNotTheValueAfterThem() {
        for (String[] c : new String[][] {
                {"κατά της Οριστικής Πράξεως του ελέγχου", "Οριστικής Πράξεως"},
                {"το Αίτημα Παροχής Πληροφοριών 9841/2023 της Δ.Ο.Υ.", "Αίτημα Παροχής Πληροφοριών"},
                {"η από 03-04-2023 Πληροφοριακή Έκθεση Ελέγχου της ΥΕΔΔΕ Αττικής", "Πληροφοριακή Έκθεση Ελέγχου"},
                {"του Κώδικα Βιβλίων και Στοιχείων", "Κώδικα Βιβλίων και Στοιχείων"},
                {"σύμφωνα με την ΣΑΔΦ Ελλάδας Γερμανίας.", "ΣΑΔΦ Ελλάδας Γερμανίας"},
                {"ΥΠΟΔΙΕΘΥΝΣΗ ΕΠΑΝΕΞΕΤΑΣΗΣ", "ΥΠΟΔΙΕΘΥΝΣΗ ΕΠΑΝΕΞΕΤΑΣΗΣ"},
                {"Την έκθεση απόψεων του Προϊσταμένου του ΚΕ.ΦΟ.Κ. Αττικής.", "ΚΕ.ΦΟ.Κ. Αττικής"},
                {"ΠΙΣΤΩΣΕΙΣ ΦΟΡ/ΚOΥ             ΕΤΟΥΣ 2020", "ΠΙΣΤΩΣΕΙΣ ΦΟΡ/ΚOΥ             ΕΤΟΥΣ 2020"},
                {"Πιστωτικό Υπόλοιπο", "Πιστωτικό Υπόλοιπο"},
                {"ΓΙΑ ΤΟΥΣ ΛΟΓΟΥΣ ΑΥΤΟΥΣ", "ΓΙΑ ΤΟΥΣ ΛΟΓΟΥΣ ΑΥΤΟΥΣ"},
                {"ΙΣΤΟΡΙΚΟ", "ΙΣΤΟΡΙΚΟ"},
                {"ΠΑΡΑ ΣΤΑΤΙΚΟ", "ΠΑΡΑ ΣΤΑΤΙΚΟ"},
                {"χρησιμοποιεί ταμειακή φορολογική μηχανή με αριθμό μητρώου", "ταμειακή φορολογική μηχανή"}}) {
            assertTrue(hardKept(c[0]).contains(c[1]), c[0] + " / " + hardKept(c[0]));
        }
        // The phrase only: the serial after it and the device's number stay out; a heading word is a heading
        // only where it stands as a label, never inside running text or a company's name.
        assertFalse(anyHardPreserved("το Αίτημα Παροχής Πληροφοριών 9841/2023 της Δ.Ο.Υ.", "9841"));
        assertFalse(anyHardPreserved("ταμειακή φορολογική μηχανή με αριθμό μητρώου DCX *****423 ,", "DCX"));
        assertFalse(anyHardPreserved("το ιστορικό του λογαριασμού", "ιστορικό"));
        assertFalse(anyHardPreserved("η εταιρεία ΠΑΡΑΣΤΑΤΙΚΑ ΜΑΡΚΟΥ ΑΕ", "ΠΑΡΑΣΤΑΤΙΚΑ"));
    }

    // ------------------------------------------------------------------ the authority's own header

    static TextUnit headerCell(String id, int table, int row, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.TABLE_CELL, text, text, List.of(),
                new TextUnit.TableCellLocation(table, row, 0, "", false));
    }

    static TextUnit para(String id, int index, String text) {
        return new TextUnit(id, "word/document.xml", UnitType.PARAGRAPH, text, text, List.of(),
                new TextUnit.ParagraphLocation(index));
    }

    static DocumentData doc(TextUnit... units) {
        return new DocumentData("d", List.of(units), List.of(), List.of());
    }

    static final TextUnit[] LETTERHEAD = {headerCell("t0", 0, 0, "ΕΛΛΗΝΙΚΗ ΔΗΜΟΚΡΑΤΙΑ"),
            headerCell("t1", 0, 1, "\tΑθήνα, 10-7-2026\tΑριθμός απόφασης: 3119"),
            headerCell("t2", 0, 2, "\tΔΙΕΥΘΥΝΣΗ ΕΠΙΛΥΣΗΣ ΔΙΑΦΟΡΩΝ\tΥΠΟΔΙΕΥΘΥΝΣΗ ΕΠΑΝΕΞΕΤΑΣΗΣ")};

    @Test
    void theAuthoritysContactValuesAreKeptInItsVerifiedHeaderAndNowhereElse() {
        // The primary gold's layout: the letterhead is a table, the contact lines are the first body paragraphs.
        DocumentData decision = doc(LETTERHEAD[0], LETTERHEAD[1], LETTERHEAD[2],
                para("p0", 3, "Ταχ. Δ/νση       : Φιλαδελφείας 8 και Σάμου"),
                para("p1", 4, "Ταχ. Κώδικας : 104 40 - Αθήνα"),
                para("p2", 5, "Τηλέφωνο        : 2131312348."),
                para("p3", 6, "E-mail              : ded.ath@aade.gr"),
                para("p4", 7, "ΑΠΟΦΑΣΗ"),
                para("p5", 8, "Ο προσφεύγων, κάτοικος Λαμίας, Τηλέφωνο: 2101234567, E-mail: g.p@example.com"),
                para("p6", 9, "όπως κρίθηκε με την απόφαση (Αριθμός απόφασης: 231) του δικαστηρίου"));
        List<String> kept = hardKeptIn(decision);
        for (String v : List.of("Φιλαδελφείας 8 και Σάμου", "104 40 - Αθήνα", "2131312348", "ded.ath@aade.gr",
                "Αθήνα, 10-7-2026", "Αριθμός απόφασης: 3119")) {
            assertTrue(kept.contains(v), v + " / " + kept);
        }
        // The appellant's own lines in the body inherit nothing, and a decision number quoted in the body is not
        // the decision's own.
        assertFalse(kept.contains("2101234567"));
        assertFalse(kept.contains("Αριθμός απόφασης: 231"));
        assertTrue(Detectors.detectAll(decision, RULES).resolverSpans().stream().anyMatch(s -> s.text().equals("g.p@example.com")
                && Resolver.isHardRedact(s, FILES.policy())));

        // The ΗUANG layout: every pair in one letterhead cell.
        assertTrue(hardKeptIn(doc(LETTERHEAD[0], headerCell("t3", 0, 3, " Ταχ. Δ/νση      : Φιλαδελφείας 8     "
                + "Ταχ. Κωδικας : 104 40 Αθήνα            Τηλέφωνο : 2131312351  E-mail : ded.ath@aade.gr")))
                .containsAll(List.of("Φιλαδελφείας 8", "104 40 Αθήνα", "2131312351")));
    }

    @Test
    void aContactValueWithoutTheAuthoritysVerifiedOwnershipIsNeverKept() {
        // No public e-mail in the block: whose lines these are is not established.
        assertEquals(List.of(), contactValues(doc(LETTERHEAD[0], para("p0", 3, "Ταχ. Δ/νση : Ερμού 5"),
                para("p1", 4, "Τηλέφωνο : 2101234567"), para("p2", 5, "E-mail : g.p@example.com"))));
        // No authority named in the header at all.
        assertEquals(List.of(), contactValues(doc(para("p0", 0, "Ταχ. Δ/νση : Ερμού 5"),
                para("p1", 1, "Τηλέφωνο : 2101234567"), para("p2", 2, "E-mail : ded.ath@aade.gr"))));
        // Another line breaks the block: the street before it is not in the verified block.
        List<String> broken = contactValues(doc(LETTERHEAD[0], para("p0", 3, "Ταχ. Δ/νση : Ερμού 5"),
                para("p1", 4, "Πληροφορίες: Γ. Παπαδόπουλος"), para("p2", 5, "Τηλέφωνο : 2131312348"),
                para("p3", 6, "E-mail : ded.ath@aade.gr")));
        assertEquals(List.of("2131312348"), broken);
        // A mobile is never an office line, even in the verified block.
        assertEquals(List.of(), contactValues(doc(LETTERHEAD[0], para("p0", 3, "Τηλέφωνο : 6912345678"),
                para("p1", 4, "E-mail : ded.ath@aade.gr"))));
        // A party's table beside the letterhead names no authority: its phone is not the authority's.
        assertEquals(List.of(), contactValues(doc(LETTERHEAD[0], headerCell("t9", 1, 0, "E-mail : ded.ath@aade.gr"),
                headerCell("t8", 1, 1, "Τηλέφωνο : 2107654321"))));
    }

    static List<String> contactValues(DocumentData document) {
        return Detectors.detectAuthorityContacts(document, RULES).stream().map(Span::text).toList();
    }
}
