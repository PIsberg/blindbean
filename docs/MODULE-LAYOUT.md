# Module Layout (JPMS reactor)

> Extracted from `CLAUDE.md` so the always-loaded context stays small. Linked from the topic index there.

The build is a Maven reactor of six library modules, each a real named module with a
`module-info.java`, plus a BOM and a thin aggregate:

| Maven artifact | JPMS module | packages | requires |
|---|---|---|---|
| `blindbean-annotations` | `se.deversity.blindbean.annotations` | annotations | — |
| `blindbean-core` | `se.deversity.blindbean.core` | core | annotations |
| `blindbean-fhe` | `se.deversity.blindbean.fhe` | fhe (+ native under `src/main/native`) | core |
| `blindbean-runtime` | `se.deversity.blindbean.runtime` | math, context, async | fhe, `jdk.incubator.vector` |
| `blindbean-processor` | `se.deversity.blindbean.processor` | processor | annotations only; `provides` Processor |
| `blindbean-junit` | `se.deversity.blindbean.junit` | junit | runtime, junit-api |
| `blindbean` (pom) | — | — | aggregate; keeps the classpath coordinate |
| `blindbean-bom` (pom) | — | — | version management |

- **`math`, `context`, `async` ship together as `-runtime`** because `BlindMath` (in `math`) dispatches
  into `context`, and `context` uses the Paillier types back — a cycle a module boundary cannot cut,
  and `BlindMath`'s package cannot move (public API + guardrail). Do not try to separate them.
- **`processor` depends only on `annotations`** — it emits runtime calls as text. Keep it that way:
  a consumer's compile path must not pull the runtime, native, or the Vector API.
- **All tests live in `blindbean-tests`** (classpath, depends on everything). New tests go there, not
  in the library modules — most are integration tests that cross module boundaries.
- **A module-path consumer** (see `module-path-tests`) `requires se.deversity.blindbean.runtime`, puts
  `blindbean-processor` on the `--processor-module-path`, and needs
  `--enable-native-access=se.deversity.blindbean.fhe` for BFV/CKKS. Classpath consumers use the
  `blindbean` aggregate (`<type>pom</type>`). That test is the guard against a wrong `exports`.
- The `@AI*` guardrail annotations are `requires static` everywhere (SOURCE retention). Each module's
  `.claude/rules/` topic files and the generated blocks in `CLAUDE.md` / `GEMINI.md` are **generated
  from those annotations, not hand-edited** — change the annotation and recompile. The reactor wiring,
  the `blindbean-processor` override trap and the RC7 lean-index marker are in `docs/CI-NOTES.md`;
  the annotations themselves are documented in the bundled `vibetags-usage` skill.
