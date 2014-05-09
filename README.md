## obfs4 - The fourbfuscator
#### Yawning Angel (yawning at torproject dot org)

### WARNING

This is pre-alpha.  Don't expect any security or wire protocol stability yet.
If you want to use something like this, you should currently probably be looking
at ScrambleSuit.

### What?

This is a look-like nothing obfuscation protocol that incorporates ideas and
concepts from Philipp Winter's ScrambleSuit protocol.  The obfs naming was
chosen primarily because it was shorter, in terms of protocol ancestery obfs4
is much closer to ScrambleSuit than obfs2/obfs3.

The notable differences between ScrambleSuit and obfs4:

 * The handshake always does a full key exchange (no such thing as a Session
   Ticket Handshake). (TODO: Reconsider this.)
 * The handshake uses the Tor Project's ntor handshake with public keys
   obfuscated via the Elligator mapping.
 * The link layer encryption uses NaCl secret boxes (Poly1305/Salsa20).

### Why not extend ScrambleSuit?

It's my protocol and I'll obfuscate if I want to.

Since a lot of the changes are to the handshaking process, it didn't make sense
to extend ScrambleSuit as writing a server implementation that supported both
handshake variants without being obscenely slow is non-trivial.

### TODO

 * Packet length obfuscation.
 * (Maybe) Make it resilient to transient connection loss.
 * (Maybe) Use IP_MTU/TCP_MAXSEG to tweak frame size.
 * Write a detailed protocol spec.
 * Code cleanups.
 * Write more unit tests.

### WON'T DO

 * I do not care that much about standalone mode.  Patches *MAY* be accepted,
   especially if they are clean and are useful to Tor users.
 * Yes, I use a bunch of code from the borg^w^wGoogle.  If that bothers you
   feel free to write your own implementation.
 * I do not care about older versions of the go runtime.

### Thanks
 * David Fifield for goptlib.
 * Adam Langley for his Elligator implementation.
 * Philipp Winter for the ScrambleSuit protocol which provided much of the
   design.
