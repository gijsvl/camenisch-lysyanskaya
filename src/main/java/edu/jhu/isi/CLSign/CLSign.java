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
import edu.jhu.isi.CLSign.keygen.KeyGen;
import edu.jhu.isi.CLSign.sign.Sign;
import edu.jhu.isi.CLSign.verify.Verify;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

import java.util.List;

public class CLSign {
    public static KeyPair keyGen(final int messageSize) {
        final Pairing pairing = KeyGen.createPairing();
        final SecretKey sk = KeyGen.createSecretKey(pairing, messageSize);
        final PublicKey pk = KeyGen.createPublicKey(pairing, sk);
        return new KeyPair(pk, sk);
    }

    public static Element commit(final List<ZrElement> messages, final PublicKey pk) {
        Element commitment = pk.getGenerator().powZn(messages.get(0));
        for (int i = 1; i < messages.size(); i++) {
            commitment = commitment.mul(pk.getZ(i).powZn(messages.get(i)));
        }
        return commitment.getImmutable();
    }

    public static Signature sign(final List<ZrElement> messages, final KeyPair keys) {
        final Element commitment = commit(messages, keys.getPk());
        return signBlind(commitment, keys);
    }

    public static Signature signBlind(final Element commitment, final KeyPair keys) {
        return Sign.sign(commitment, keys);
    }

    public static boolean verify(final List<ZrElement> messages, final Signature sigma, final PublicKey pk) {
        return Verify.aFormedCorrectly(sigma, pk)
                && Verify.bFormedCorrectly(sigma, pk)
                && Verify.cFormedCorrectly(messages, sigma, pk);
    }
}
