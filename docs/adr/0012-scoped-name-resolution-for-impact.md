# ADR 0012: Scoped name resolution for change impact

- **Status:** Accepted
- **Date:** 2026-11-23

## Context

Impact analysis matched a changed symbol to every occurrence of its name.
On commit `c3a009a` (9 changed files) it reported 3,518 references across 80
files. Of those, 3,348 came from three generic names:

- `report`, a trait method, matched every `.report()` call.
- `new` matched every `Type::new`.
- `review` matched every variable called `review`.

On JavaScript changes, locals inside test callbacks counted as changed
symbols. A changed spec file was also scanned against itself, giving up to
108 self-references. Vue components were not analysed at all.

The literature agrees on the cause
([review](../research/review-literature.md), section 1):

- **Bare-name matching is what makes static impact imprecise.** Call/use
  links unfiltered reach about 2% precision (Hassan & Holt 2004).
- **Scoped resolution recovers precision.** Resolving through imports,
  modules and assignment flow gives about 99% precision, at a recall cost
  (Salis et al. 2021).
- **Most useful signal is one hop away.** Limiting analysis to direct
  dependents raised precision from 73% to 84% (Hattori et al. 2008).

## Decision

Impact keeps one hop of direct references and resolves each occurrence by
what it can syntactically name.

1. **Declaration kinds.** A changed Rust declaration is one of four kinds,
   each matched only by the occurrences that can name it:
   - **value** (free function, constant, static): a final path segment;
   - **type**: any path segment;
   - **module**: only a path prefix;
   - **associated item of an owner** (an `impl` or `trait` item):
     - `Owner::name`;
     - `Self::name` in a file that names the owner;
     - a method call in a file that names the owner.

   Naming the owner stands in for the type or trait being in scope, which a
   method call needs and syntax alone cannot prove.
2. **Locals shadow items.** These are bindings, not references:
   - an unqualified path or macro token that names a parameter, or a
     `let`, closure, `for` or match-arm binding (including `let` inside
     macro bodies);
   - an unqualified call to an item the file declares itself.
3. **Use trees.** A `use` path prefix names a module or type. Only the final
   name or rename can import a function.
4. **TypeScript and JavaScript declarations** count only outside every
   brace. A `const` inside a function or callback is a local.
5. **No self-edges outside Rust.** Rust keeps same-file edges, because
   in-file test modules exercise the change.
6. **Vue components:**
   - their `<script>` blocks are scanned with other TypeScript and
     JavaScript, with template and style lines blanked so line numbers stay
     true;
   - a changed component contributes its PascalCase file name as its
     symbol;
   - tsserver results never suppress `.vue` matches, because tsserver does
     not load components.

## Consequences

**Measured precision gains:**

| Commit | Before | After |
|---|---|---|
| `c3a009a` | 3,518 references across 80 files | 71 references across 10 files |
| `3eaabd9` (JS) | 108 self-references | 2 references, from the file that mounts the edited component |

**Recall costs:**
- A method call on a value whose type the file never names, such as a type
  returned from another module's function, is now missed.
- A Rust item reached only through a glob import, and shadowed by nothing,
  is still found.
- These references are labelled syntax-derived, as before. Type-resolved
  Rust analysis would remove both costs and remains future work.

**Still open:**
- Co-change history as a second signal, to be combined with this one by
  union with labelled provenance.
- Vue template-only usages are not scanned.
