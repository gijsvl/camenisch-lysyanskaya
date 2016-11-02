package edu.jhu.isi.CLSign.entities;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.List;

public class PublicKey {
    private Pairing pairing;
    private Element generator;
    private Element generatorT;
    private Element X;
    private Element Y;
    private List<Element> Z = new ArrayList<>();

    public PublicKey(final Pairing pairing, final Element generator, final Element generatorT, final Element x, final Element y, final List<Element> z) {
        this.pairing = pairing;
        this.generator = generator;
        this.generatorT = generatorT;
        X = x;
        Y = y;
        Z = z;
    }

    public Pairing getPairing() {
        return pairing;
    }

    public Element getGenerator() {
        return generator;
    }

    public Element getX() {
        return X;
    }

    public Element getY() {
        return Y;
    }

    public Element getZ(final int index) {
        return Z.get(index);
    }

    public List<Element> getZ() {
        return Z;
    }
}
