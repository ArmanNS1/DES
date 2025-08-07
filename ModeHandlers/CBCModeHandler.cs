using System;
using System.Collections;

namespace DES.ModeHandlers
{
    public sealed class CBCModeHandler : OperationModeHandler
    {
        public CBCModeHandler(byte[] key, byte[] iv) : base(key, iv) { }

        public override byte[] Encrypt(byte[] plaintext)
        {
            ValidateBlockSize(plaintext);
            var result = new byte[plaintext.Length];

            BitArray previousBlock = new BitArray(InitializationVector);

            for (int i = 0; i < plaintext.Length; i += 8)
            {
                BitArray currentBlock = ConvertToBitArray(plaintext, i);

                currentBlock.Xor(previousBlock);

                BitArray encryptedBlock = DESEncryption.EncryptBlock(currentBlock, RoundKeys);

                CopyBitArrayToBytes(encryptedBlock, result, i);

                previousBlock = encryptedBlock;
            }

            return result;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            ValidateBlockSize(ciphertext);
            var result = new byte[ciphertext.Length];

            BitArray previousBlock = new BitArray(InitializationVector);

            for (int i = 0; i < ciphertext.Length; i += 8)
            {
                BitArray currentBlock = ConvertToBitArray(ciphertext, i);
                
                BitArray nextPreviousBlock = new BitArray(currentBlock);

                BitArray decryptedBlock = DESEncryption.DecryptBlock(currentBlock, RoundKeys);

                decryptedBlock.Xor(previousBlock);

                CopyBitArrayToBytes(decryptedBlock, result, i);

                previousBlock = nextPreviousBlock;
            }

            return result;
        }
    }
}
