## obfs4 - The obfourscator
#### Yawning Angel (yawning at torproject dot org)

### What?

This is a look-like nothing obfuscation protocol that incorporates ideas and
concepts from Philipp Winter's ScrambleSuit protocol.  The obfs naming was
chosen primarily because it was shorter, in terms of protocol ancestery obfs4
is much closer to ScrambleSuit than obfs2/obfs3.

The notable differences between ScrambleSuit and obfs4:

 * The handshake always does a full key exchange (no such thing as a Session
   Ticket Handshake).
 * The handshake uses the Tor Project's ntor handshake with public keys
   obfuscated via the Elligator 2 mapping.
 * The link layer encryption uses NaCl secret boxes (Poly1305/XSalsa20).

As an added bonus, obfs4proxy also supports acting as an obfs2/3 client and
bridge to ease the transition to the new protocol.

### Why not extend ScrambleSuit?

It's my protocol and I'll obfuscate if I want to.

Since a lot of the changes are to the handshaking process, it didn't make sense
to extend ScrambleSuit as writing a server implementation that supported both
handshake variants without being obscenely slow is non-trivial.

### Dependencies

Build time library dependencies are handled by go get automatically but are
listed for clarity.

 * Go 1.2.0 or later.  Debian stable packages Go 1.0.2 which is missing several
   things obfs4 depends on like SHA256.
 * go.crypto (https://code.google.com/p/go.crypto)
 * go.net (https://code.google.com/p/go.net)
 * ed25519/extra25519 (https://github.com/agl/ed25519/extra25519)
 * SipHash-2-4 (https://github.com/dchest/siphash)
 * goptlib (https://git.torproject.org/pluggable-transports/goptlib.git)

### Thanks

 * David Fifield for goptlib.
 * Adam Langley for his Elligator implementation.
 * Philipp Winter for the ScrambleSuit protocol which provided much of the
   design.
