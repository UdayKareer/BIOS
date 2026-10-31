# Agent Rules

- **Assigned Folder:** Only read or edit files inside `FRONTEND/` (or `/frontend`) under the `BIOS` folder.
- **Zero Unrequested Exploration:** ONLY read or edit files explicitly mentioned with `@` or inside `FRONTEND/`. Do NOT grep or scan the rest of the repository.
- **No Repeated File Reads:** Never read the same file or line range twice in a single turn. Act immediately once located.
- **No Tests, Linting, or Refactoring:** Never write unit tests, run linters/typechecks, or refactor working code unless explicitly told.
- **Concise Output:** Output code changes only. Do not write introductory plans, architectural essays, or closing summaries.
