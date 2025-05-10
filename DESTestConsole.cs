using System.Text;
using DES.ModeHandlers;

namespace DES
{
    public class DESTestConsole
    {
        public static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            Console.WriteLine("DES Algorithm Test Program");
            Console.WriteLine("========================\n");

            // دریافت متن از کاربر
            Console.WriteLine("Please enter the text to encrypt:");
            string plaintext = Console.ReadLine() ?? "Default text for testing";

            // دریافت کلید از کاربر
            Console.WriteLine("\nPlease enter the encryption key (8 characters):");
            string keyInput = Console.ReadLine() ?? "TestKey1";
            byte[] key = Encoding.UTF8.GetBytes(keyInput.PadRight(8)[..8]);

            // دریافت بردار اولیه
            Console.WriteLine(
                "\nPlease enter the initial vector (8 characters) or leave it blank for default value:"
            );
            string ivInput = Console.ReadLine() ?? "12345678";
            byte[] iv = Encoding.UTF8.GetBytes(ivInput.PadRight(8)[..8]);

            // انتخاب حالت رمزنگاری
            Console.WriteLine("\nPlease select the encryption mode:");
            Console.WriteLine("1. ECB (Electronic Codebook)");
            Console.WriteLine("2. CBC (Cipher Block Chaining)");
            Console.WriteLine("3. CFB (Cipher Feedback)");
            Console.WriteLine("4. OFB (Output Feedback)");
            Console.WriteLine("5. CTR (Counter)");

            string modeInput = Console.ReadLine() ?? "1";
            if (!int.TryParse(modeInput, out int mode) || mode < 1 || mode > 5)
            {
                mode = 1; // ECB به عنوان پیش‌فرض
                Console.WriteLine("Invalid mode. Using ECB mode.");
            }

            // تبدیل متن به بایت
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            // اضافه کردن پدینگ برای اطمینان از اینکه طول داده مضربی از 8 است
            int paddingLength = 8 - (plaintextBytes.Length % 8);
            if (paddingLength < 8)
            {
                byte[] paddedPlaintext = new byte[plaintextBytes.Length + paddingLength];
                Array.Copy(plaintextBytes, paddedPlaintext, plaintextBytes.Length);
                for (int i = plaintextBytes.Length; i < paddedPlaintext.Length; i++)
                {
                    paddedPlaintext[i] = (byte)paddingLength;
                }
                plaintextBytes = paddedPlaintext;
            }

            // ایجاد هندلر مناسب بر اساس حالت انتخاب شده
            OperationModeHandler handler;
            switch (mode)
            {
                case 2:
                    handler = new CBCModeHandler(key, iv);
                    Console.WriteLine("\nUsing CBC mode");
                    break;
                case 3:
                    handler = new CFBModeHandler(key, iv);
                    Console.WriteLine("\nUsing CFB mode");
                    break;
                case 4:
                    handler = new OFBModeHandler(key, iv);
                    Console.WriteLine("\nUsing OFB mode");
                    break;
                case 5:
                    handler = new CTRModeHandler(key, iv);
                    Console.WriteLine("\nUsing CTR mode");
                    break;
                default:
                    handler = new ECBModeHandler(key);
                    Console.WriteLine("\nUsing ECB mode");
                    break;
            }

            try
            {
                // رمزنگاری
                Console.WriteLine("\nEncrypting...");
                byte[] ciphertext = handler.Encrypt(plaintextBytes);
                string base64Ciphertext = Encoding.UTF8.GetString(ciphertext);
                Console.WriteLine($"Encrypted text (Base64): {base64Ciphertext}");

                // رمزگشایی
                Console.WriteLine("\nDecrypting...");
                byte[] decryptedBytes = handler.Decrypt(ciphertext);

                // حذف پدینگ
                int lastByte = decryptedBytes[^1];
                if (lastByte > 0 && lastByte <= 8)
                {
                    bool validPadding = true;
                    for (int i = decryptedBytes.Length - lastByte; i < decryptedBytes.Length; i++)
                    {
                        if (decryptedBytes[i] != lastByte)
                        {
                            validPadding = false;
                            break;
                        }
                    }

                    if (validPadding)
                    {
                        byte[] unpaddedBytes = new byte[decryptedBytes.Length - lastByte];
                        Array.Copy(decryptedBytes, unpaddedBytes, unpaddedBytes.Length);
                        decryptedBytes = unpaddedBytes;
                    }
                }

                string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                Console.WriteLine($"Decrypted text: {decryptedText}");

                // بررسی صحت رمزگشایی
                if (decryptedText == plaintext)
                {
                    Console.WriteLine("\n✓ Encryption and decryption completed successfully!");
                }
                else
                {
                    Console.WriteLine(
                        "\n✗ خطا در رمزگشایی! متن رمزگشایی شده با متن اصلی مطابقت ندارد."
                    );
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nError: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}
