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
        final Element generator = pairing.getG1().newRandomElement();
        final Element generatorT = pairing.getGT().newRandomElement();
        final List<Element> Z = sk.getZ().stream()
                .map(generator::powZn).collect(Collectors.toList());
        return new PublicKey(pairing, generator, generatorT,
                generator.powZn(sk.getX()), generator.powZn(sk.getY()), Z);
    }

    private static SecretKey createSecretKey(final Pairing pairing, final int messageSize) {
        final ZrElement[] z = new ZrElement[messageSize];
        for (int i = 0; i < messageSize; i++) {
            z[i] = (ZrElement) pairing.getZr().newZeroElement();
        }
        return new SecretKey((ZrElement) pairing.getZr().newRandomElement(),
                (ZrElement) pairing.getZr().newRandomElement(), z);
    }

    private static Pairing createPairing() {
        int rBits = 160;
        int qBits = 512;

        final TypeACurveGenerator pairingGenerator = new TypeACurveGenerator(rBits, qBits);
        final PairingParameters params = pairingGenerator.generate();
        return PairingFactory.getPairing(params);
    }

    public static Signature sign(final List<ZrElement> messages, final SecretKey sk, final PublicKey pk) {
        final Element a = pk.getPairing().getG1().newRandomElement();
        final List<Element> A = sk.getZ().stream().map(a::powZn).collect(Collectors.toCollection(ArrayList::new));
        final Element b = a.powZn(sk.getY());
        final List<Element> B = A.stream().map(Ai -> Ai.powZn(sk.getY())).collect(Collectors.toCollection(ArrayList::new));
        final Element cPart = pk.getPairing().getG1().newOneElement();
        final ZrElement xTimesY = sk.getX().mul(sk.getY());
        for (int i = 1; i < messages.size(); i++) {
            cPart.mul(A.get(i).powZn(xTimesY.mul(messages.get(i))));
        }
        final Element c = a.powZn(sk.getX().add(xTimesY.mul(messages.get(0)))).mul(cPart);

        return new Signature(a, b, c, A, B);
    }

    public static boolean verify(final List<ZrElement> messages, final Signature sigma, final PublicKey pk) {
        return false;
    }
}
