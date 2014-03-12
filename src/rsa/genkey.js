/**
 * Generate RSA key pair
 *
 * @param bitlen desired modulus length, default is 2048
 * @param e public exponent, default is 65537
 */
function RSA_generateKey ( bitlen, e ) {
    bitlen = bitlen || 2048;
    e = e || 65537;

    if ( bitlen < 512 )
        throw new IllegalArgumentError("bit length is too small");
    if ( pow2_ceil(bitlen) !== bitlen )
        throw new IllegalArgumentError("bit length should be a power of 2");

    // TODO
}
