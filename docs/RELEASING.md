# Releasing BlindBean

Coordinates are `se.deversity:blindbean` (packages live under `se.deversity.blindbean.*`). Cutting a
release is tagging one — `.github/workflows/release.yml` fires on `v*`:

```bash
mvn versions:set -DnewVersion=0.2.0   # pom must already say 0.2.0
git tag v0.2.0 && git push origin v0.2.0
```

## The tag must match the POM

The tag **must** match `<version>` in `pom.xml`; the workflow refuses to run otherwise, because a
Release labelled v0.2.0 shipping a 0.1.0 jar is worse than no release. SNAPSHOT versions are refused
outright.

## What the workflow does

It builds the three native libraries, runs the full SEAL-backed suite on Windows, signs, uploads to
Maven Central, and attaches the jar + all three natives + `SHA256SUMS.txt` to a GitHub Release.

**`autoPublish` is `false`** — the bundle uploads and waits for a human to press Publish on
central.sonatype.com, because a Central release is irreversible (a version can never be replaced or
withdrawn).

Central needs four secrets — `MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE`, `CENTRAL_USERNAME`,
`CENTRAL_PASSWORD` — and until they are set the workflow **skips Central and still cuts the GitHub
Release**, so a tag can never half-publish. See the header of `release.yml`.

## What Central mandates

Central mandates POM `name`/`description`/`url`/`licenses`/`developers`/`scm` plus signed jar,
**sources jar and javadoc jar** — a missing javadoc jar is the classic cause of a release that
uploads then silently fails validation. All of that lives in the `release` profile, which is off by
default so an ordinary `mvn install` never tries to sign anything. Verify it without publishing:

```bash
mvn -Prelease package -DskipTests -Dgpg.skip=true   # should produce -sources and -javadoc jars
```

Javadoc needs `--enable-preview`/`--add-modules` passed explicitly (`additionalJOptions`) or it
refuses to parse the sources it is documenting.

## Release checklist

- [ ] `pom.xml` `<version>` set to the release version (no `-SNAPSHOT`)
- [ ] `mvn -Prelease package -DskipTests -Dgpg.skip=true` produces `-sources` and `-javadoc` jars
- [ ] Vendored VibeTags skill copies (`.claude/skills/`, `.gemini/skills/`) match the
      `${vibetags.version}` pinned in `pom.xml` — see `docs/CI-NOTES.md`
- [ ] Tag matches the POM version exactly
- [ ] After the workflow completes, press Publish on central.sonatype.com
