using System;
using System.Collections;

namespace DES.ModeHandlers
{
    public sealed class CTRModeHandler : OperationModeHandler
    {
        public CTRModeHandler(byte[] key, byte[] iv) : base(key, iv) { }

        public override byte[] Encrypt(byte[] plaintext)
        {
            ValidateBlockSize(plaintext);
            var result = new byte[plaintext.Length];

            // Initialize counter with IV
            BitArray counter = new BitArray(InitializationVector);

            for (int i = 0; i < plaintext.Length; i += 8)
            {
                // Encrypt counter to generate keystream
                BitArray keystream = DESEncryption.EncryptBlock(counter, RoundKeys);

                // Get current plaintext block
                BitArray plaintextBlock = ConvertToBitArray(plaintext, i);

                // XOR keystream with plaintext
                BitArray ciphertextBlock = new BitArray(keystream);
                ciphertextBlock.Xor(plaintextBlock);

                // Store the result
                CopyBitArrayToBytes(ciphertextBlock, result, i);

                // Increment counter for next block
                IncrementCounter(counter);
            }

            return result;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            // CTR decryption is identical to encryption
            return Encrypt(ciphertext);
        }

        private static void IncrementCounter(BitArray counter)
        {
            // Treat the last 32 bits as a counter
            bool carry = true;
            for (int i = counter.Length - 1; i >= counter.Length - 32 && carry; i--)
            {
                bool newBit = counter[i] ^ carry;
                carry = counter[i] && carry;
                counter[i] = newBit;
            }
        }
    }
}