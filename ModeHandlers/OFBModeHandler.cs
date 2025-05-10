using System;
using System.Collections;

namespace DES.ModeHandlers
{
    public sealed class OFBModeHandler : OperationModeHandler
    {
        public OFBModeHandler(byte[] key, byte[] iv) : base(key, iv) { }

        public override byte[] Encrypt(byte[] plaintext)
        {
            ValidateBlockSize(plaintext);
            var result = new byte[plaintext.Length];

            // Initialize shift register with IV
            BitArray shiftRegister = new BitArray(InitializationVector);

            for (int i = 0; i < plaintext.Length; i += 8)
            {
                // Encrypt shift register to generate keystream
                BitArray keystream = DESEncryption.EncryptBlock(shiftRegister, RoundKeys);

                // Get current plaintext block
                BitArray plaintextBlock = ConvertToBitArray(plaintext, i);

                // XOR keystream with plaintext
                BitArray ciphertextBlock = new BitArray(keystream);
                ciphertextBlock.Xor(plaintextBlock);

                // Store the result
                CopyBitArrayToBytes(ciphertextBlock, result, i);

                // Update shift register for next iteration
                shiftRegister = keystream;
            }

            return result;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            // OFB decryption is identical to encryption
            return Encrypt(ciphertext);
        }
    }
}