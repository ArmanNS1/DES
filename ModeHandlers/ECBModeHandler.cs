using System;
using System.Collections;

namespace DES.ModeHandlers
{
    public sealed class ECBModeHandler : OperationModeHandler
    {
        public ECBModeHandler(byte[] key) : base(key) { }

        public override byte[] Encrypt(byte[] plaintext)
        {
            ValidateBlockSize(plaintext);
            var result = new byte[plaintext.Length];

            for (int i = 0; i < plaintext.Length; i += 8)
            {
                BitArray block = ConvertToBitArray(plaintext, i);
                BitArray encryptedBlock = DESEncryption.EncryptBlock(block, RoundKeys);
                CopyBitArrayToBytes(encryptedBlock, result, i);
            }

            return result;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            ValidateBlockSize(ciphertext);
            var result = new byte[ciphertext.Length];

            for (int i = 0; i < ciphertext.Length; i += 8)
            {
                BitArray block = ConvertToBitArray(ciphertext, i);
                BitArray decryptedBlock = DESEncryption.DecryptBlock(block, RoundKeys);
                CopyBitArrayToBytes(decryptedBlock, result, i);
            }

            return result;
        }
    }
}