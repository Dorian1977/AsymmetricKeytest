using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Asymmetric_Key_test
{
    class Symmetric_Encrypted
    {
        static public byte[] Encrypt(string plainText, byte[] Key)
        {
            byte[] encrypted;
            byte[] iv = new byte[16];
            try
            {
                // Create a new AesManaged.    
                using (AesManaged aes = new AesManaged())
                {
                    ICryptoTransform encryptor = aes.CreateEncryptor(Key, iv); 
                    using (MemoryStream ms = new MemoryStream())
                    {
                        // Create crypto stream using the CryptoStream class. This class is the key to encryption    
                        // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream    
                        // to encrypt    
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            // Create StreamWriter and write data to a stream    
                            using (StreamWriter sw = new StreamWriter(cs))
                            {
                                sw.Write(plainText);
                            }
                            encrypted = ms.ToArray();
                        }
                    }
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
            // Return encrypted data    
            return encrypted;
        }
        static public string Decrypt(byte[] cipherText, byte[] Key)
        {
            byte[] iv = new byte[16];
            string plaintext = null;
            // Create AesManaged    
            try
            {
                using (AesManaged aes = new AesManaged())
                {
                    // Create a decryptor    
                    aes.IV = iv;
                    ICryptoTransform decryptor = aes.CreateDecryptor(Key, aes.IV);
                    // Create the streams used for decryption.    
                    using (MemoryStream ms = new MemoryStream(cipherText))
                    {
                        // Create crypto stream    
                        using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            // Read crypto stream    
                            using (StreamReader reader = new StreamReader(cs))
                                plaintext = reader.ReadToEnd();
                        }
                    }
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
            return plaintext;
        }
    }
}
