package edu.jhu.isi.CLSign.proof;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

public class Proof {
    private Element commitment;
    private List<Element> openings;

    public Proof(final Element commitment, final List<Element> openings) {
        this.commitment = commitment;
        this.openings = openings;
    }

    public Element getCommitment() {
        return commitment;
    }

    public void setCommitment(final Element commitment) {
        this.commitment = commitment;
    }

    public List<Element> getOpenings() {
        return openings;
    }
}
