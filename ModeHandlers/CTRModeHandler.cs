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
            
            BitArray counter = new BitArray(InitializationVector);

            for (int i = 0; i < plaintext.Length; i += 8)
            {
                BitArray keystream = DESEncryption.EncryptBlock(counter, RoundKeys);

                BitArray plaintextBlock = ConvertToBitArray(plaintext, i);

                BitArray ciphertextBlock = new BitArray(keystream);
                ciphertextBlock.Xor(plaintextBlock);

                CopyBitArrayToBytes(ciphertextBlock, result, i);

                IncrementCounter(counter);
            }

            return result;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            return Encrypt(ciphertext);
        }

        private static void IncrementCounter(BitArray counter)
        {
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
