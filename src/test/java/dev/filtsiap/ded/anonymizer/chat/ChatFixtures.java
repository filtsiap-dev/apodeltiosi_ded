package dev.filtsiap.ded.anonymizer.chat;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A small, hand-made ChatLists for unit tests. Every ordinary word the unit tests use must be in
 * GREEK or ENGLISH below, or the uncommon-word rule masks it; that is the point of the rule.
 */
final class ChatFixtures {
    private ChatFixtures() {
    }

    static List<String> words(String spaceSeparated) {
        return Arrays.asList(spaceSeparated.trim().split("\\s+"));
    }

    /** Nominatives expanded through GreekInflection, as the list builder does. */
    static List<String> names(String nominatives) {
        return words(nominatives).stream().map(GreekFold::fold)
                .flatMap(n -> GreekInflection.forms(n).stream()).collect(Collectors.toList());
    }

    static final String GREEK = """
            καλησπέρα με λένε και θέλω να ακυρώσω τη συνδρομή η μου είπε ότι το πρόβλημα λύθηκε ομάδα
            πήρε νίκη χθες οπότε είμαι χαρούμενος δεν έχω καμία ελπίδα λυθεί αυτό θέμα σοφία της όμως
            βοηθά εδώ είναι μητέρα ήλιος σήμερα καίει ο στο γραφείο ευχαριστώ πολύ ήσουν εξυπηρετική γεια
            σας κύριε κυρία από τον την του τμήμα μίλησα λογιστήριο απαντά πελάτης χρόνια γιος πώς μπορώ
            βοηθήσω κόρη ονομάζομαι λέγομαι υπογραφή πλατεία πλάκα έχει που λογαριασμός ήρθε διπλός
            σούπερ μάρκετ κοντά μένω μένει στην κατάστημα έχετε δάφνη θα γιορτή πολλά για αγίου άγιος
            γιορτή εκκλησία απέναντι οδός οδό στη κατοικώ ζω δουλεύω αλλά νέα διεύθυνση ειρήνη ησυχία
            όχι άλλα τηλεφωνήματα φορές αριθμός καλή βοήθεια
            """;

    static final String ENGLISH = "hi i m can you help me with my bill smith bot ok thanks for the";

    static final ChatLists LISTS = ChatLists.of(
            names("Γιώργος Μαρία Ελένη Νίκη Ελπίδα Σοφία Αναστασία Ηλίας Στέλιος Φωτεινή Δάφνη Αθηνά"),
            names("Παπαδόπουλος Παππάς"),
            words(GREEK),
            words("Αθήνα Αμερική Αμερικής Ιούνιος Ιουνίου Πάσχα Ελλάδα Λάρισα"),
            words(ENGLISH),
            words("κλπ τηλ αφμ αμκα δεη ευδαπ iphone android"));
}
