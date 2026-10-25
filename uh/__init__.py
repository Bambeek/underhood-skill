"""underhood: free tools Claude uses to mod games and apps (no paid services).

Subcommands (see `uh --help`):
  scan      find installed games and fingerprint one: engine, runtime, anti-cheat, mod loaders, routes
  probe     identify a file: magic, entropy, zlib streams, XOR key from known plaintext
  comfy     generate images locally with ComfyUI (no API key)
  sprite    cut out, fit, pixelate, recolor and pack 2D sprites
  render3d  render a GLB into sprite frames from a game's camera (Blender)
  video     compile styled showcase videos, trim, mux
  win       Windows (and WSL): screenshots, recording with game-only audio, input, processes
  backup    snapshot and restore save folders before you touch them
  publish   lint a mod folder before sharing: game files, decompiled code, secrets, credits
  kb        the knowledge base: search prior field notes, write your own, check it, open a PR
"""

__version__ = "1.0.0"
