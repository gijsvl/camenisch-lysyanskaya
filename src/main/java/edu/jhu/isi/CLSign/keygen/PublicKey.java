/*
 * Copyright (c) 2016 Gijs Van Laer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package edu.jhu.isi.CLSign.keygen;

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
    private List<Element> W = new ArrayList<>();

    public PublicKey(final Pairing pairing, final Element generator, final Element generatorT, final Element x, final Element y, final List<Element> z, final List<Element> w) {
        this.pairing = pairing;
        this.generator = generator;
        this.generatorT = generatorT;
        X = x;
        Y = y;
        Z = z;
        W = w;
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

    public Element getW(final int index) {
        return W.get(index);
    }

    public List<Element> getW() {
        return W;
    }
}
