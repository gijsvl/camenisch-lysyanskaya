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
package edu.jhu.isi.CLSign;

import edu.jhu.isi.CLSign.entities.KeyPair;
import edu.jhu.isi.CLSign.entities.PublicKey;
import edu.jhu.isi.CLSign.entities.SecretKey;
import edu.jhu.isi.CLSign.entities.Signature;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class CLSign {
    public static KeyPair keyGen(final int messageSize) {
        final Pairing pairing = createPairing();
        final SecretKey sk = createSecretKey(pairing, messageSize);
        final PublicKey pk = createPublicKey(pairing, sk);
        return new KeyPair(pk, sk);
    }

    private static PublicKey createPublicKey(final Pairing pairing, final SecretKey sk) {
        final Element generator = pairing.getG1().newRandomElement().getImmutable();
        final Element generatorT = pairing.getGT().newRandomElement().getImmutable();
        final List<Element> Z = sk.getZ().stream()
                .map(generator::powZn).collect(Collectors.toList());
        return new PublicKey(pairing, generator, generatorT,
                generator.powZn(sk.getX()), generator.powZn(sk.getY()), Z);
    }

    private static SecretKey createSecretKey(final Pairing pairing, final int messageSize) {
        final ZrElement[] z = new ZrElement[messageSize];
        for (int i = 0; i < messageSize; i++) {
            z[i] = (ZrElement) pairing.getZr().newRandomElement().getImmutable();
        }
        return new SecretKey((ZrElement) pairing.getZr().newRandomElement().getImmutable(),
                (ZrElement) pairing.getZr().newRandomElement().getImmutable(), z);
    }

    private static Pairing createPairing() {
        int rBits = 160;
        int qBits = 512;

        final TypeACurveGenerator pairingGenerator = new TypeACurveGenerator(rBits, qBits);
        final PairingParameters params = pairingGenerator.generate();
        return PairingFactory.getPairing(params);
    }

    public static Signature sign(final List<ZrElement> messages, final KeyPair keys) {
        final PublicKey pk = keys.getPk();
        final SecretKey sk = keys.getSk();
        final Element a = pk.getPairing().getG1().newRandomElement().getImmutable();
        final List<Element> A = sk.getZ().stream().map(a::powZn).collect(Collectors.toCollection(ArrayList::new));
        final Element b = a.powZn(sk.getY()).getImmutable();
        final List<Element> B = A.stream().map(Ai -> Ai.powZn(sk.getY())).collect(Collectors.toCollection(ArrayList::new));
        final Element cPart = pk.getPairing().getG1().newOneElement();
        final ZrElement xTimesY = sk.getX().mul(sk.getY());
        for (int i = 1; i < messages.size(); i++) {
            cPart.mul(A.get(i).powZn(xTimesY.mul(messages.get(i))));
        }
        final Element c = a.powZn(sk.getX().add(xTimesY.mul(messages.get(0)))).mul(cPart).getImmutable();

        return new Signature(a, b, c, A, B);
    }

    public static boolean verify(final List<ZrElement> messages, final Signature sigma, final PublicKey pk) {
        return aFormedCorrectly(sigma, pk)
                && bFormedCorrectly(sigma, pk)
                && cFormedCorrectly(messages, sigma, pk);
    }

    private static boolean aFormedCorrectly(final Signature sigma, final PublicKey pk) {
        final Pairing p = pk.getPairing();
        for (int i = 0; i < sigma.getAList().size(); i++) {
            if (!p.pairing(sigma.getA(), pk.getZ(i))
                    .isEqual(p.pairing(pk.getGenerator(), sigma.getAList().get(i)))) {
                return false;
            }
        }
        return true;
    }

    private static boolean bFormedCorrectly(final Signature sigma, final PublicKey pk) {
        final Pairing p = pk.getPairing();
        if (!p.pairing(sigma.getA(), pk.getY()).isEqual(p.pairing(pk.getGenerator(), sigma.getB()))) {
            return false;
        }
        for (int i = 0; i < sigma.getBList().size(); i++) {
            if (!p.pairing(sigma.getAList().get(i), pk.getY())
                    .isEqual(p.pairing(pk.getGenerator(), sigma.getBList().get(i)))) {
                return false;
            }
        }
        return true;
    }

    private static boolean cFormedCorrectly(final List<ZrElement> messages, final Signature sigma, final PublicKey pk) {
        final Pairing p = pk.getPairing();
        final Element product = p.getGT().newOneElement();
        for (int i = 1; i < messages.size(); i++) {
            product.mul(p.pairing(pk.getX(), sigma.getBList().get(i)).powZn(messages.get(i)));
        }
        final Element lhs = p.pairing(pk.getX(), sigma.getA())
                .mul(p.pairing(pk.getX(), sigma.getB()).powZn(messages.get(0)))
                .mul(product);
        return lhs.isEqual(p.pairing(pk.getGenerator(), sigma.getC()));
    }
}
