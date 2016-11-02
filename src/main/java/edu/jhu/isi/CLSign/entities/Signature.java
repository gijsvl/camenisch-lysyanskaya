package edu.jhu.isi.CLSign.entities;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.List;

public class Signature {
    private Element a;
    private Element b;
    private Element c;
    private List<Element> A = new ArrayList<>();
    private List<Element> B = new ArrayList<>();

    public Signature(final Element a, final Element b, final Element c, final List<Element> a1, final List<Element> b1) {
        this.a = a;
        this.b = b;
        this.c = c;
        A = a1;
        B = b1;
    }

    public Element getA() {
        return a;
    }

    public Element getB() {
        return b;
    }

    public Element getC() {
        return c;
    }

    public List<Element> getAList() {
        return A;
    }

    public List<Element> getBList() {
        return B;
    }

    public void setB(final Element b) {
        this.b = b;
    }
}
