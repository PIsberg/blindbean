package se.deversity.blindbean.loadtest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Prints a fixed-width table to stdout and to {@code target/}, so a run can be diffed against a
 * previous release.
 *
 * <p>Two things that matter for a file meant to be compared across machines and versions:
 * <ul>
 *   <li>Every number is formatted with {@link Locale#ROOT}. The first run of this harness emitted
 *       "18,1" ms on a Swedish JVM — a decimal comma makes a results file undiffable, and worse,
 *       silently misread by anything parsing it.</li>
 *   <li>Column widths are computed from the <em>content</em> at render time, not guessed from the
 *       headers, or a long cell simply runs into the next column.</li>
 * </ul>
 */
final class Report {

    /** A table: a header row plus its data rows. */
    private record Table(List<String[]> rows) {}

    private sealed interface Block permits Head, Sect, Tab, Note {}
    private record Head(String text) implements Block {}
    private record Sect(String title, String why) implements Block {}
    private record Tab(Table table) implements Block {}
    private record Note(String text) implements Block {}

    private final List<Block> blocks = new ArrayList<>();
    private final Path file;
    private Table current;

    Report(String name) {
        this.file = Path.of("target", name + ".txt");
        blocks.add(new Head("BlindBean — " + name));
    }

    void section(String title, String why) {
        current = null;
        blocks.add(new Sect(title, why));
    }

    void columns(String... headers) {
        current = new Table(new ArrayList<>());
        current.rows().add(headers);
        blocks.add(new Tab(current));
    }

    void row(Object... cells) {
        if (current == null) throw new IllegalStateException("columns() before row()");
        String[] s = new String[cells.length];
        for (int i = 0; i < cells.length; i++) s[i] = String.valueOf(cells[i]);
        current.rows().add(s);
    }

    void note(String s) {
        current = null;
        blocks.add(new Note(s));
    }

    /** Locale-independent number formatting — see the class javadoc. */
    static String num(String pattern, Object... args) {
        return String.format(Locale.ROOT, pattern, args);
    }

    void flush() {
        StringBuilder out = new StringBuilder();
        for (Block b : blocks) {
            switch (b) {
                case Head h -> {
                    out.append(h.text()).append('\n');
                    out.append("=".repeat(100)).append('\n');
                }
                case Sect s -> {
                    out.append('\n').append("## ").append(s.title()).append('\n');
                    out.append("   ").append(wrap(s.why(), 94, "   ")).append("\n\n");
                }
                case Note n -> out.append("\n   → ").append(wrap(n.text(), 92, "     ")).append('\n');
                case Tab t -> renderTable(out, t.table());
            }
        }
        String text = out.toString();
        System.out.println(text);
        try {
            Files.createDirectories(file.getParent());
            Files.writeString(file, text);
            System.out.println("written: " + file.toAbsolutePath());
        } catch (IOException e) {
            System.err.println("could not write " + file + ": " + e.getMessage());
        }
    }

    private static void renderTable(StringBuilder out, Table t) {
        List<String[]> rows = t.rows();
        if (rows.isEmpty()) return;
        int cols = rows.stream().mapToInt(r -> r.length).max().orElse(0);

        int[] w = new int[cols];
        for (String[] r : rows) {
            for (int i = 0; i < r.length; i++) w[i] = Math.max(w[i], r[i].length());
        }
        for (int i = 0; i < cols; i++) w[i] += 2;

        out.append(pad(rows.get(0), w)).append('\n');
        int total = 0;
        for (int x : w) total += x;
        out.append("-".repeat(total)).append('\n');
        for (int i = 1; i < rows.size(); i++) {
            out.append(pad(rows.get(i), w)).append('\n');
        }
    }

    private static String pad(String[] cells, int[] w) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cells.length; i++) {
            sb.append(cells[i]);
            if (i < cells.length - 1) sb.append(" ".repeat(Math.max(1, w[i] - cells[i].length())));
        }
        return sb.toString().stripTrailing();
    }

    private static String wrap(String s, int width, String indent) {
        List<String> lines = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (String word : s.split(" ")) {
            if (cur.length() + word.length() + 1 > width) {
                lines.add(cur.toString());
                cur.setLength(0);
            }
            cur.append(cur.isEmpty() ? "" : " ").append(word);
        }
        lines.add(cur.toString());
        return String.join("\n" + indent, lines);
    }
}
