# FNV decompilation: custom exe

Tools that build a custom FNV executable on your own machine, from the source code in
[fnv_decomp](https://github.com/momusdigital/fnv_decomp) and your own copy of the game. Windows only for now.

- **Kept apart on purpose.** fnv_decomp holds source code only and proves that it matches the original. Building an
  executable from that source lives here, in its own repository.
- **The decomp is a submodule.** It sits in `decomp/`, pinned to a commit of fnv_decomp's main. Clone with
  `git clone --recurse-submodules`, or run `git submodule update --init` after cloning.
- **Nothing of the game is here.** No executables, no game files, no game data. What the build needs from the game is
  read from your own copy on your own machine, and everything it produces stays in the git-ignored `.local/` folder.
  **Never share the executable, or anything else the build produces.**
- **No copy-protection removal.** The tools need a plain executable from your own copy and contain no decryption.
- **You need the game.** You need your own legally obtained copy of FNV for PC, version 1.4.0.525.

The build tools are being moved here from [fnv_decomp#31](https://github.com/momusdigital/fnv_decomp/pull/31).

## Legal

Fallout, Fallout: New Vegas, Bethesda, Bethesda Softworks and
ZeniMax are trademarks or registered trademarks of ZeniMax Media Inc., a Microsoft company, in the U.S. and/or other
countries. The game was developed by Obsidian Entertainment and published by Bethesda Softworks. Steam is a trademark
of Valve Corporation. All other trademarks belong to their respective holders. This project is not affiliated with or
endorsed by any of them.

You need your own legally obtained copy of the game, and you are responsible for following its licence terms and the
law where you live.

If you hold rights in this material and want something changed or removed, write to contact@fnvdecomp.com. We will
respond promptly and comply.

No licence is granted for this repository; see `LICENSE`.
