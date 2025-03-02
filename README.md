AES

same key for encryption and decryption
taken in group of bits
128 bits or more as the input and 128 bits as output

round one has 4 transformation
and so on
number of rounds vary on one criterion
last round will have 3 transformations 

 Every round will have different key (128 bits) the orignial key is M bytes, 

Key size:
128 bits then rounds 10
192 => 12
256 => 14 

AES considers the input as a column-major arrangement of 32 bits, so as to create a 4bx4b matrix 

operations in each round 
SubBytes
ShiftRows
MixColumns
Add Round Key


SubBytes: Implements substitution from s-box a lookup table
(never substitute byte by itself and never its compliment)

ShiftRows:
every row is shifted a particular number of times

MixRound:
Performs matrix multiplication on each column essentially to mix the columns (skipped int he last round)

Add round keys
XOR the 16 bytes with the round key

This process is repeated until all the data to be encrypted undergoes this process.


for decryption, the reverse methodology in used

Add round key
Inverse MixColumns
ShiftRows
Inverse SubByte

this is an ECB mode implmentation