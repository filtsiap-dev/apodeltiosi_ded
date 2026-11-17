package dev.filtsiap.ded.anonymizer.chat.build;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The subset of Hunspell's .aff format the LibreOffice el_GR and en_US dictionaries use: SET,
 * single-character flags, PFX/SFX groups with cross-product. Continuation classes on an affix
 * ("add/flags") are dropped, which can only under-generate; any FLAG type other than the default
 * is refused rather than misread.
 */
final class HunspellAffixes {
    record Rule(String strip, String add, Pattern condition) {
    }

    record Group(boolean prefix, boolean crossProduct, List<Rule> rules) {
    }

    private final Charset charset;
    private final Map<Character, Group> groups;

    private HunspellAffixes(Charset charset, Map<Character, Group> groups) {
        this.charset = charset;
        this.groups = groups;
    }

    Charset charset() {
        return charset;
    }

    static HunspellAffixes parse(byte[] aff) {
        Charset charset = StandardCharsets.ISO_8859_1;
        for (String line : new String(aff, StandardCharsets.ISO_8859_1).split("\\R")) {
            String[] f = line.strip().split("\\s+");
            if (f.length >= 2 && f[0].equals("SET")) {
                charset = Charset.forName(f[1].equalsIgnoreCase("ISO8859-7") ? "ISO-8859-7" : f[1]);
            }
        }
        Map<Character, Group> groups = new LinkedHashMap<>();
        for (String line : new String(aff, charset).split("\\R")) {
            int hash = line.indexOf('#');
            String[] f = (hash < 0 ? line : line.substring(0, hash)).strip().split("\\s+");
            if (f[0].equals("FLAG")) {
                throw new IllegalArgumentException("unsupported FLAG type: " + (f.length > 1 ? f[1] : ""));
            }
            if (!f[0].equals("PFX") && !f[0].equals("SFX")) {
                continue;
            }
            boolean prefix = f[0].equals("PFX");
            char flag = f[1].charAt(0);
            if (f.length == 4 && !groups.containsKey(flag)) {          // header: PFX A Y 1
                groups.put(flag, new Group(prefix, f[2].equals("Y"), new ArrayList<>()));
            } else if (f.length >= 5) {                                // rule: SFX B strip add condition
                String strip = f[2].equals("0") ? "" : f[2];
                String add = f[3].equals("0") ? "" : f[3].split("/", 2)[0];
                String cond = f[4].equals(".") ? "" : f[4];
                Pattern condition = Pattern.compile(prefix ? "^" + cond : cond + "$");
                groups.get(flag).rules().add(new Rule(strip, add, condition));
            }
        }
        return new HunspellAffixes(charset, groups);
    }

    /** Every form of one .dic line ("word", "word/FLAGS", optionally followed by morphology fields). */
    List<String> expand(String dicLine) {
        String entry = dicLine.strip().split("\\s+", 2)[0];
        int slash = entry.indexOf('/');
        String word = slash < 0 ? entry : entry.substring(0, slash);
        String flags = slash < 0 ? "" : entry.substring(slash + 1);
        Set<String> out = new LinkedHashSet<>();
        out.add(word);
        List<String> prefixed = new ArrayList<>();
        for (char flag : flags.toCharArray()) {
            Group g = groups.get(flag);
            if (g == null || !g.prefix()) {
                continue;
            }
            for (Rule r : g.rules()) {
                if (r.condition().matcher(word).find() && word.startsWith(r.strip())) {
                    String form = r.add() + word.substring(r.strip().length());
                    out.add(form);
                    if (g.crossProduct()) {
                        prefixed.add(form);
                    }
                }
            }
        }
        for (char flag : flags.toCharArray()) {
            Group g = groups.get(flag);
            if (g == null || g.prefix()) {
                continue;
            }
            List<String> bases = new ArrayList<>();
            bases.add(word);
            if (g.crossProduct()) {
                bases.addAll(prefixed);
            }
            for (String base : bases) {
                for (Rule r : g.rules()) {
                    if (r.condition().matcher(base).find() && base.endsWith(r.strip())) {
                        out.add(base.substring(0, base.length() - r.strip().length()) + r.add());
                    }
                }
            }
        }
        return new ArrayList<>(out);
    }
}
