#!/usr/bin/env bash
# Regenerates every SVG under docs/diagrams/ with code-karta, so the next refresh is one command
# instead of a reconstruction (#225: the previous set was drawn by code-karta 0.1.0 with arguments
# nobody recorded).
#
# Usage:  tools/regenerate-diagrams.sh [path/to/code-karta-cli-<version>-all.jar]
#
# Without an argument it uses the CLI from the local Maven repository at KARTA_VERSION, fetching it
# first if it is missing. Run it from anywhere; it works from the repository root. Commit the
# resulting SVGs together with the code change that made them stale.
set -euo pipefail

KARTA_VERSION="${KARTA_VERSION:-0.4.0}"   # keep in step with code-karta-core in the root pom.xml
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

JAR="${1:-$HOME/.m2/repository/se/deversity/codekarta/code-karta-cli/$KARTA_VERSION/code-karta-cli-$KARTA_VERSION-all.jar}"
if [[ ! -f "$JAR" ]]; then
    ./mvnw -q -B dependency:get -Dartifact="se.deversity.codekarta:code-karta-cli:$KARTA_VERSION:jar:all"
fi
[[ -f "$JAR" ]] || { echo "code-karta CLI not found at $JAR" >&2; exit 1; }

karta() {
    java -jar "$JAR" "$@" > /dev/null
}

OUT=docs/diagrams

# Library modules: class diagram, JPMS module diagram, stitched sequence diagram.
for module in blindbean-core blindbean-fhe blindbean-junit blindbean-processor blindbean-runtime; do
    src="$module/src/main/java"
    karta --input "$src"                  --output "$OUT/$module" --output-name class-diagram.svg
    karta --input "$src/module-info.java" --output "$OUT/$module" --output-name module-diagram.svg
    karta --input "$src" --sequence-only  --output "$OUT/$module" --output-name sequence-diagram.svg
done

# Annotations: no call graph worth drawing, but Scheme is an enum, so a state diagram instead.
src=blindbean-annotations/src/main/java
karta --input "$src"                  --output "$OUT/blindbean-annotations" --output-name class-diagram.svg
karta --input "$src/module-info.java" --output "$OUT/blindbean-annotations" --output-name module-diagram.svg
karta --input "$src" --state-machine  --output "$OUT/blindbean-annotations" --output-name state-machine-diagram.svg

# The example is a separate consumer project with no module-info.java.
src=blindbean-example/src/main/java
karta --input "$src"                 --output "$OUT/blindbean-example" --output-name class-diagram.svg
karta --input "$src" --sequence-only --output "$OUT/blindbean-example" --output-name sequence-diagram.svg

# Whole repository: module communication, and one stitched sequence diagram including the tests.
karta --input . --modules-only                   --output "$OUT" --output-name modules-diagram.svg
karta --input . --sequence-only --include-tests  --output "$OUT" --output-name sequence-diagram.svg

echo "Regenerated $(find "$OUT" -name '*.svg' | wc -l) diagrams under $OUT with code-karta $KARTA_VERSION."
