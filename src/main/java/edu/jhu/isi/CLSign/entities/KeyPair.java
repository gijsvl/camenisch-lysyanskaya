package edu.jhu.isi.CLSign.entities;


public class KeyPair {
    private PublicKey pk;
    private SecretKey sk;

    public KeyPair(final PublicKey pk, final SecretKey sk) {
        this.pk = pk;
        this.sk = sk;
    }

    public PublicKey getPk() {
        return pk;
    }

    public SecretKey getSk() {
        return sk;
    }
}
