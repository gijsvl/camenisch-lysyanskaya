package edu.jhu.isi.CLSign;

import edu.jhu.isi.CLSign.entities.KeyPair;
import edu.jhu.isi.CLSign.entities.PublicKey;
import edu.jhu.isi.CLSign.entities.SecretKey;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
        assertEquals(pk.getGenerator().powZn(sk.getX()), pk.getX());
        assertEquals(pk.getGenerator().powZn(sk.getY()), pk.getY());
        for (int i = 0; i < messageSize; i++) {
            assertEquals(pk.getGenerator().powZn(sk.getZ(i)), pk.getZ(i));
        }
        assertEquals(pk.getPairing().getG1(), pk.getPairing().getG2());
    }

    @Test
    public void testSign() throws Exception {

    }

    @Test
    public void testVerify() throws Exception {

    }

}