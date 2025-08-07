using System;
using System.Collections;

namespace DES.ModeHandlers
{
    public sealed class CFBModeHandler : OperationModeHandler
    {
        public CFBModeHandler(byte[] key, byte[] iv) : base(key, iv) { }

        public override byte[] Encrypt(byte[] plaintext)
        {
            ValidateBlockSize(plaintext);
            var result = new byte[plaintext.Length];

            BitArray shiftRegister = new BitArray(InitializationVector);

            for (int i = 0; i < plaintext.Length; i += 8)
            {
                BitArray encryptedRegister = DESEncryption.EncryptBlock(shiftRegister, RoundKeys);

                BitArray plaintextBlock = ConvertToBitArray(plaintext, i);

                encryptedRegister.Xor(plaintextBlock);

                CopyBitArrayToBytes(encryptedRegister, result, i);

                shiftRegister = encryptedRegister;
            }

            return result;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            ValidateBlockSize(ciphertext);
            var result = new byte[ciphertext.Length];

            BitArray shiftRegister = new BitArray(InitializationVector);

            for (int i = 0; i < ciphertext.Length; i += 8)
            {
                BitArray encryptedRegister = DESEncryption.EncryptBlock(shiftRegister, RoundKeys);

                BitArray ciphertextBlock = ConvertToBitArray(ciphertext, i);

                BitArray decryptedBlock = new BitArray(encryptedRegister);
                decryptedBlock.Xor(ciphertextBlock);

                CopyBitArrayToBytes(decryptedBlock, result, i);

                shiftRegister = ciphertextBlock;
            }

            return result;
        }
    }
}
