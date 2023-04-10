# Padding-Oracle-Attack-Proof-Of-Concept

The files beginning with "by_hand" are the ones used by the following along in my article here:


The full attack script consists of the two files that begin with "full_". The bashscript is the file to run. It will be able to decrypt the very last block of plaintext by itself as a proof of concept. It does this by creating a file known_values.txt and appending to it. This file is meant to contain the values of the intermediate block referred to as I3 in my article. By finding this block finding the plaintext is done through xoring with a known ciphertext block.
