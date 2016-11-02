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


### License ###
Copyright (c) 2016 Gijs Van Laer

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.