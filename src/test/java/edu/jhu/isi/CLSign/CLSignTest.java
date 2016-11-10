package edu.jhu.isi.CLSign;

import edu.jhu.isi.CLSign.keygen.KeyPair;
import edu.jhu.isi.CLSign.keygen.PublicKey;
import edu.jhu.isi.CLSign.keygen.SecretKey;
import edu.jhu.isi.CLSign.proof.Proof;
import edu.jhu.isi.CLSign.sign.Signature;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import org.junit.Test;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CLSignTest {
    @Test
    public void testKeyGen() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final PublicKey pk = keyPair.getPk();
        final SecretKey sk = keyPair.getSk();
        assertNotNull(pk);
        assertNotNull(sk);
        assertEquals(messageSize, sk.getZ().size());
        assertEquals(messageSize, pk.getZ().size());
        assertEquals(messageSize, pk.getW().size());
        assertEquals(pk.getGenerator().powZn(sk.getX()), pk.getX());
        assertEquals(pk.getGenerator().powZn(sk.getY()), pk.getY());
        for (int i = 0; i < messageSize; i++) {
            assertEquals(pk.getGenerator().powZn(sk.getZ(i)), pk.getZ(i));
            assertEquals(pk.getY().powZn(sk.getZ(i)), pk.getW(i));
        }
        assertEquals(pk.getPairing().getG1(), pk.getPairing().getG2());
    }

    @Test
    public void testSign() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final List<ZrElement> messages = IntStream.range(0, messageSize)
                .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
                .collect(Collectors.toList());
        final Signature sigma = CLSign.sign(messages, keyPair);
        assertNotNull(sigma.getA());
        assertNotNull(sigma.getB());
        assertNotNull(sigma.getC());
        assertEquals(messageSize, sigma.getAList().size());
        assertEquals(messageSize, sigma.getBList().size());
    }

    @Test
    public void testVerify() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final List<ZrElement> messages = IntStream.range(0, messageSize)
                .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
                .collect(Collectors.toList());
        final Signature sigma = CLSign.sign(messages, keyPair);
        assertTrue(CLSign.verify(messages, sigma, keyPair.getPk()));
    }

    @Test
    public void testVerifyFalseA() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final List<ZrElement> messages = IntStream.range(0, messageSize)
                .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
                .collect(Collectors.toList());
        final Signature sigma = CLSign.sign(messages, keyPair);
        sigma.getAList().set(0, keyPair.getPk().getPairing().getG1().newRandomElement());
        assertTrue(!CLSign.verify(messages, sigma, keyPair.getPk()));
    }

    @Test
    public void testVerifyFalseB1() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final List<ZrElement> messages = IntStream.range(0, messageSize)
                .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
                .collect(Collectors.toList());
        final Signature sigma = CLSign.sign(messages, keyPair);
        sigma.setB(keyPair.getPk().getPairing().getG1().newRandomElement());
        assertTrue(!CLSign.verify(messages, sigma, keyPair.getPk()));
    }

    @Test
    public void testVerifyFalseB2() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final List<ZrElement> messages = IntStream.range(0, messageSize)
                .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
                .collect(Collectors.toList());
        final Signature sigma = CLSign.sign(messages, keyPair);
        sigma.getBList().set(0, keyPair.getPk().getPairing().getG1().newRandomElement());
        assertTrue(!CLSign.verify(messages, sigma, keyPair.getPk()));
    }

    @Test
    public void testInstantiate() throws Exception {
        final CLSign clSign = new CLSign();
        assertNotNull(clSign);
    }

    @Test(expected = IllegalStateException.class)
    public void testCommit_wrongMessageSize() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final List<ZrElement> messages = IntStream.range(0, messageSize + 1)
                .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
                .collect(Collectors.toList());
        CLSign.commit(messages, keyPair.getPk());
    }

    @Test(expected = IllegalStateException.class)
    public void testPartialCommit_wrongMessageSize() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final List<ZrElement> messages = IntStream.range(0, messageSize + 1)
                .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
                .collect(Collectors.toList());
        CLSign.partialCommit(messages, keyPair.getPk());
    }

    @Test
    public void testBlindSignature() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final List<ZrElement> messages = IntStream.range(0, messageSize)
                .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
                .collect(Collectors.toList());
        final Element commitment = CLSign.commit(messages, keyPair.getPk());
        final Proof proof = CLSign.proofCommitment(commitment, messages, keyPair.getPk());
        final Signature sigma = CLSign.signBlind(commitment, proof, keyPair);
        assertTrue(CLSign.verify(messages, sigma, keyPair.getPk()));
    }

    @Test
    public void testPartiallyBlindSignature() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final List<ZrElement> messages = IntStream.range(0, messageSize)
                .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
                .collect(Collectors.toList());
        final Element partialCommitment = CLSign.partialCommit(messages.subList(0, messageSize - 2), keyPair.getPk());
        final Proof proof = CLSign.proofCommitment(partialCommitment, messages.subList(0, messageSize - 2), keyPair.getPk());
        final Signature sigma = CLSign.signPartiallyBlind(messages.subList(messageSize - 2, messageSize),
                partialCommitment, proof, keyPair);
        assertTrue(CLSign.verify(messages, sigma, keyPair.getPk()));
    }

    @Test
    public void testBlindSignature_badProof() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final List<ZrElement> messages = IntStream.range(0, messageSize)
                .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
                .collect(Collectors.toList());
        final Element commitment = CLSign.commit(messages, keyPair.getPk());
        final Proof proof = CLSign.proofCommitment(commitment, messages, keyPair.getPk());
        proof.setCommitment(keyPair.getPk().getPairing().getG1().newRandomElement());
        final Signature sigma = CLSign.signBlind(commitment, proof, keyPair);
        assertNull(sigma);
    }

    @Test
    public void testPartiallyBlindSignature_badProof() throws Exception {
        final int messageSize = 5;
        final KeyPair keyPair = CLSign.keyGen(messageSize);
        final List<ZrElement> messages = IntStream.range(0, messageSize)
                .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
                .collect(Collectors.toList());
        final Element partialCommitment = CLSign.partialCommit(messages.subList(0, messageSize - 2), keyPair.getPk());
        final Proof proof = CLSign.proofCommitment(partialCommitment, messages.subList(0, messageSize - 2), keyPair.getPk());
        proof.setCommitment(keyPair.getPk().getPairing().getG1().newRandomElement());
        final Signature sigma = CLSign.signPartiallyBlind(messages.subList(messageSize - 2, messageSize),
                partialCommitment, proof, keyPair);
        assertNull(sigma);
    }
}