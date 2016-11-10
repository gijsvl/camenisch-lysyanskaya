package edu.jhu.isi.CLSign.proof;

import edu.jhu.isi.CLSign.keygen.PublicKey;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Prover {
    public static List<Element> computeProof(final List<Element> t, final List<ZrElement> messages, final Element challenge) {
        final List<Element> s = new ArrayList<>();
        for (int i = 0; i < t.size(); i++) {
            s.add(messages.get(i).mul(challenge).add(t.get(i)));
        }
        return s;
    }

    public static Element computeProofComm(final PublicKey pk, final List<Element> t, final int size) {
        t.add(pk.getPairing().getZr().newRandomElement());
        Element proofComm = pk.getGenerator().powZn(t.get(0));
        for (int i = 1; i < size; i++) {
            t.add(pk.getPairing().getZr().newRandomElement());
            proofComm = proofComm.mul(pk.getZ(i).powZn(t.get(i)));
        }
        return proofComm;
    }

    public static Element computeChallenge(final Element commitment, final Element proofComm, final PublicKey pk) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest((Arrays.toString(proofComm.toBytes()) +
                    Arrays.toString(commitment.toBytes())).getBytes());
            return pk.getPairing().getZr().newElementFromBytes(hash);
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static boolean verify(final Element commitment, final Proof proof, final PublicKey pk) {
        Element lhs = pk.getGenerator().powZn(proof.getOpenings().get(0));
        for (int i = 1; i < proof.getOpenings().size(); i++) {
            lhs = lhs.mul(pk.getZ(i).powZn(proof.getOpenings().get(i)));
        }
        final Element rhs = commitment.powZn(computeChallenge(commitment, proof.getCommitment(), pk)).mul(proof.getCommitment());
        return lhs.equals(rhs);
    }
}
