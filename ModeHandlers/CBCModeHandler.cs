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

            // Initialize previous block with IV
            BitArray previousBlock = new BitArray(InitializationVector);

            for (int i = 0; i < plaintext.Length; i += 8)
            {
                // Get current plaintext block
                BitArray currentBlock = ConvertToBitArray(plaintext, i);

                // XOR with previous ciphertext block (or IV for first block)
                currentBlock.Xor(previousBlock);

                // Encrypt the XORed block
                BitArray encryptedBlock = DESEncryption.EncryptBlock(currentBlock, RoundKeys);

                // Store the result
                CopyBitArrayToBytes(encryptedBlock, result, i);

                // Update previous block for next iteration
                previousBlock = encryptedBlock;
            }

            return result;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            ValidateBlockSize(ciphertext);
            var result = new byte[ciphertext.Length];

            // Initialize previous block with IV
            BitArray previousBlock = new BitArray(InitializationVector);

            for (int i = 0; i < ciphertext.Length; i += 8)
            {
                // Get current ciphertext block
                BitArray currentBlock = ConvertToBitArray(ciphertext, i);

                // Store current block for next iteration (before decryption)
                BitArray nextPreviousBlock = new BitArray(currentBlock);

                // Decrypt the current block
                BitArray decryptedBlock = DESEncryption.DecryptBlock(currentBlock, RoundKeys);

                // XOR with previous ciphertext block (or IV for first block)
                decryptedBlock.Xor(previousBlock);

                // Store the result
                CopyBitArrayToBytes(decryptedBlock, result, i);

                // Update previous block for next iteration
                previousBlock = nextPreviousBlock;
            }

            return result;
        }
    }
}