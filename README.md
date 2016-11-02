# Camenisch-Lysyanskaya Signatures #
Implementation of the CL signature scheme

## ⚠ Warning ⚠ ##
This is an experimental library and is only at its first version. The API could still be updated in the near future.
I cannot guarantee the security of this library, and one should not use this in production.

### Usage ###
Note: random messages are generated in this example
Keygen:
```java
final KeyPair keyPair = CLSign.keyGen(messageSize);
final List<ZrElement> messages = IntStream.range(0, messageSize)
        .mapToObj(i -> (ZrElement) keyPair.getPk().getPairing().getZr().newRandomElement().getImmutable())
        .collect(Collectors.toList());
```

Sign:
```java
final Signature sigma = CLSign.sign(messages, keyPair);
```

Verify:
```java
CLSign.verify(messages, sigma, keyPair.getPk());
```

### References ###
Jan Camenisch, Anna Lysyanskaya. **"Signature Schemes and Anonymous Credentials from Bilinear Maps."** *CRYPTO 2004*
