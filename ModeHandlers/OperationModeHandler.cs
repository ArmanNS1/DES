using System;
using System.Collections;

namespace DES.ModeHandlers
{
    public abstract class OperationModeHandler
    {
        protected readonly byte[] InitializationVector;
        protected readonly List<BitArray> RoundKeys;
        protected readonly DESEncryption DesEncryption;

        protected OperationModeHandler(byte[] key, byte[]? iv = null)
        {
            InitializationVector = iv ?? new byte[8];
            RoundKeys = DesKeyScheduler.GenerateRoundKeys(key);
            DesEncryption = new DESEncryption();
        }

        public abstract byte[] Encrypt(byte[] plaintext);
        public abstract byte[] Decrypt(byte[] ciphertext);

        protected static void ValidateBlockSize(byte[] data)
        {
            if (data.Length % 8 != 0)
                throw new ArgumentException("Invalid block size. Data must be 64-bit aligned.");
        }

        protected static BitArray ConvertToBitArray(byte[] data, int startIndex)
        {
            byte[] block = new byte[8];
            Array.Copy(data, startIndex, block, 0, 8);
            return new BitArray(block);
        }

        protected static void CopyBitArrayToBytes(BitArray bits, byte[] destination, int startIndex)
        {
            byte[] block = new byte[8];
            bits.CopyTo(block, 0);
            Array.Copy(block, 0, destination, startIndex, 8);
        }
    }
}
