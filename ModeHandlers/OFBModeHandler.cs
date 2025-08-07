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

            BitArray shiftRegister = new BitArray(InitializationVector);

            for (int i = 0; i < plaintext.Length; i += 8)
            {
                BitArray keystream = DESEncryption.EncryptBlock(shiftRegister, RoundKeys);

                BitArray plaintextBlock = ConvertToBitArray(plaintext, i);

                BitArray ciphertextBlock = new BitArray(keystream);
                ciphertextBlock.Xor(plaintextBlock);

                CopyBitArrayToBytes(ciphertextBlock, result, i);

                shiftRegister = keystream;
            }

            return result;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            return Encrypt(ciphertext);
        }
    }
}
