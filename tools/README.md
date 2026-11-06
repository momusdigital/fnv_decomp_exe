# Local custom executable builder

Start with [Building a custom exe](../README.md#building-a-custom-exe). The only supported entry point is
`python tools/custom_exe.py extract|build|run`. Run from the repository root. 64-bit Python 3.10+ and Windows are
required; Wine is untested. Install `capstone` and `psutil` in the Python environment used for the commands.

All generated artifacts stay in ignored `.local/custom-exe/`. None may be committed or distributed. Extraction
validates the owner's plain image with the upstream fingerprints before writing output. No encrypted-image conversion
exists. The fixed output location prevents accidental installation over the original. Do not force-add ignored files.

The recipe and `decomp/tools/msvc.py` supply the compiler flags and compiler selection. Recipe objects are cached by source,
header and compiler hashes. Extraction checks function bytes and aggregate EH coverage using the upstream matcher;
the native linker separately checks ownership, reachability and relocation identity. In particular, identical code
bytes do not justify merging COMDATs with different relocation targets. Literal operands without an original HIGHLOW
relocation remain literals. Original initialization order and TLS storage come from the locally extracted tables.

Data export produces C++ structures with symbolic pointer initializers and checks their compiled bytes, field offsets,
relocations, labels and alignment. Unknown data layouts remain opaque. Remaining runtime gaps and resources are still
extracted from the executable; this is not a build using only recovered source. The full private input copy remains a
validation oracle and is not linked wholesale.

The final native link uses `/NODEFAULTLIB /OPT:REF /OPT:NOICF`, the original entry-point identity and generated import
libraries. It never uses `/FORCE` or chooses a differing duplicate body arbitrarily. Static checks must all pass before
the distinctly named executable is emitted. They do not prove all game behavior, so report reproducible crashes with
the function and offset printed by the bounded debugger launcher. Keep game-derived artifacts private.

Implementation modules are internal: `standalone` indexes and adapts private object copies, `phase2_policy` enforces
ownership and reachability, `gen_image` supplies missing image pieces, `gen_aliases` binds proven identities, and
`data_source` exports and recompiles storage. No module writes to the input executable or game installation.
