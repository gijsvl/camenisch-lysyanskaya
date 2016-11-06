package edu.jhu.isi.CLSign.verify;

import edu.jhu.isi.CLSign.keygen.PublicKey;
import edu.jhu.isi.CLSign.sign.Signature;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

import java.util.List;

public class Verify {
    public static boolean aFormedCorrectly(final Signature sigma, final PublicKey pk) {
        final Pairing p = pk.getPairing();
        for (int i = 0; i < sigma.getAList().size(); i++) {
            if (!p.pairing(sigma.getA(), pk.getZ(i))
                    .isEqual(p.pairing(pk.getGenerator(), sigma.getAList().get(i)))) {
                return false;
            }
        }
        return true;
    }

    public static boolean bFormedCorrectly(final Signature sigma, final PublicKey pk) {
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

    public static boolean cFormedCorrectly(final List<ZrElement> messages, final Signature sigma, final PublicKey pk) {
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
