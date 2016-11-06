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
package edu.jhu.isi.CLSign.sign;

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
