using System.Collections;

namespace DES
{
    public class DesKeyScheduler
    {
        // Permuted Choice 1 (PC-1) table (64-bit to 56-bit, parity bits removed)
        private static readonly int[] PC1 =
        {
            57,
            49,
            41,
            33,
            25,
            17,
            9,
            1,
            58,
            50,
            42,
            34,
            26,
            18,
            10,
            2,
            59,
            51,
            43,
            35,
            27,
            19,
            11,
            3,
            60,
            52,
            44,
            36,
            63,
            55,
            47,
            39,
            31,
            23,
            15,
            7,
            62,
            54,
            46,
            38,
            30,
            22,
            14,
            6,
            61,
            53,
            45,
            37,
            29,
            21,
            13,
            5,
            28,
            20,
            12,
            4
        };

        // Permuted Choice 2 (PC-2) table (56-bit to 48-bit)
        private static readonly int[] PC2 =
        {
            14,
            17,
            11,
            24,
            1,
            5,
            3,
            28,
            15,
            6,
            21,
            10,
            23,
            19,
            12,
            4,
            26,
            8,
            16,
            7,
            27,
            20,
            13,
            2,
            41,
            52,
            31,
            37,
            47,
            55,
            30,
            40,
            51,
            45,
            33,
            48,
            44,
            49,
            39,
            56,
            34,
            53,
            46,
            42,
            50,
            36,
            29,
            32
        };

        // Left shift schedule for each round
        private static readonly int[] Shifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        public static List<BitArray> GenerateRoundKeys(byte[] initialKey64bit)
        {
            // Convert key to BitArray and apply PC-1
            BitArray keyBits = new(initialKey64bit); // 64 bits
            BitArray key56 = Permute(keyBits, PC1); // Remove parity → 56 bits

            // Split into C and D (28 bits each)
            BitArray C = new(28);
            BitArray D = new(28);
            for (int i = 0; i < 28; i++)
            {
                C[i] = key56[i];
                D[i] = key56[i + 28];
            }

            // Generate 16 round keys
            var roundKeys = new List<BitArray>();
            for (int round = 0; round < 16; round++)
            {
                // Perform left shifts
                C = LeftShift(C, Shifts[round]);
                D = LeftShift(D, Shifts[round]);

                // Combine C and D
                BitArray combinedCD = new(56);
                for (int i = 0; i < 28; i++)
                {
                    combinedCD[i] = C[i];
                    combinedCD[i + 28] = D[i];
                }

                // Apply PC-2 to get the round key
                BitArray roundKey = Permute(combinedCD, PC2);
                roundKeys.Add(roundKey);
            }

            return roundKeys;
        }

        private static BitArray Permute(BitArray input, int[] table)
        {
            BitArray result = new(table.Length);
            for (int i = 0; i < table.Length; i++)
                result[i] = input[table[i] - 1]; // -1 because DES tables are 1-indexed
            return result;
        }

        private static BitArray LeftShift(BitArray input, int count)
        {
            BitArray result = new(input.Length);
            for (int i = 0; i < input.Length; i++)
                result[i] = input[(i + count) % input.Length];
            return result;
        }
    }
}
