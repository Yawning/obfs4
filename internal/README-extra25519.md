This includes a copy of the edwards25519 and extra25519 packages authored
by agl, that formerly lived at github.com/agl/ed25519 as of the commit
5312a61534124124185d41f09206b9fef1d88403 with the following changes:

 * Import paths fixed up.

 * The unused Ed25519->X25519 key conversion routines were removed.

 * `UnsafeBroken` was prefixed to the routines that are known to be
   severely flawed.

The only reason this is being done (despite agl's wishes that the code
base dies, which I wanted to respect) is so people stop bothering me
about it.

Do not ask me questions about this.
Do not use it in other projects.
Do not use it in anything new.
Do not expect me to maintain this beyond ensuring it continues to build.

All I want is to be left alone.
