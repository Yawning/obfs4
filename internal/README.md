The x25519ell2 package provides X25519 obfuscated with Elligator 2, with
special care taken to handle cofactor related issues, and fixes for the
bugs in agl's original Elligator2 implementation.

All existing versions prior to the migration to the new code (anything
that uses agl's code) are fatally broken, and trivial to distinguish via
some simple math.  For more details see Loup Vaillant's writings on the
subject.  Any bugs in the implementation are mine, and not his.

Representatives created by this implementation will correctly be decoded
by existing implementations.  Public keys created by this implementation
be it via the modified scalar basepoint multiply or via decoding a
representative will be somewhat non-standard, but will interoperate with
a standard X25519 scalar-multiply.

As the obfs4 handshake does not include the decoded representative in
any of it's authenticated handshake digest calculations, this change is
fully-backward compatible (though the non-upgraded side of the connection
will still be trivially distinguishable from random).

##### Maintainer's rant

Honestly, it is possible to create a better obfuscation protocol than
obfs4, and it's shelf-life expired years ago.  No one should be using
it for anything at this point, and no one should have been using it
for anything for the past however many years since I first started
telling people to stop using it.

People should also have listened when I told them repeatedly that there
are massive issues in the protocol.

 * Do not ask me questions about this.
 * Do not use it in other projects.
 * Do not use it in anything new.
 * Use a prime order group instead of this nonsense especially if you
   are doing something new.
 * All I want is to be left alone.
