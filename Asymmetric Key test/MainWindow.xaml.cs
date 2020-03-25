using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;

using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Globalization;

namespace Asymmetric_Key_test
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        UnicodeEncoding ByteConverter = new UnicodeEncoding();
        RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
        AesManaged aes = new AesManaged();
        const string keyPath = @"c:\temp\symmetric.dat";
        const string accessCodePath = @"c:\temp\accessCode.dat";
        byte[] plaintext;
        byte[] encryptedtext;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void encryptBt_Click(object sender, RoutedEventArgs e)
        {//asymmetric
            MessageBox.Show("Public key + " + RSA.ToXmlString(false));
            MessageBox.Show("Private key + " + RSA.ToXmlString(true));
            plaintext = ByteConverter.GetBytes(txtplainTB.Text);
            encryptedtext = Asymmetric_Encrypted.Encryption(plaintext, RSA.ExportParameters(false), false);
            txtencryptedTB.Text = Convert.ToBase64String(encryptedtext);
        }

        private void decryptBt_Click(object sender, RoutedEventArgs e)
        {//asymmetric
            byte[] decryptedtex = Asymmetric_Encrypted.Decryption(encryptedtext, RSA.ExportParameters(true), false);
            txtdecryptedTB.Text = ByteConverter.GetString(decryptedtex);
        }

        private void ReadSymmetricKey_Click(object sender, RoutedEventArgs e)
        {
            if(!File.Exists(keyPath))
            {
                File.WriteAllBytes(keyPath, aes.Key);
            }
            else
            {
                aes.Key = File.ReadAllBytes(keyPath);
                //Convert.ToBase64String (to read: Convert.FromBase64String) 
                MessageBox.Show("AES read key + " + Convert.ToBase64String(aes.Key));
            }
        }

        private void SimpleEncryptBt_Click(object sender, RoutedEventArgs e)
        {//symmetric
         // Encrypt string    
            //string key = Convert.ToBase64String(aes.Key);
            //string key1 = ByteConverter.GetString(aes.Key);
            //MessageBox.Show("AES key + " + key);
            //MessageBox.Show("AES IV + " + ByteConverter.GetString(aes.IV));
            encryptedtext = Symmetric_Encrypted.Encrypt(txtplainTB.Text, aes.Key);
            txtencryptedTB.Text = Convert.ToBase64String(encryptedtext);
        }

        private void WriteAllBytes()
        {
            throw new NotImplementedException();
        }

        private void SimpleDecryptBt_Click(object sender, RoutedEventArgs e)
        {//symmetric
            // Decrypt the bytes to a string.    
            //txtdecryptedTB.Text = Symmetric_Encrypted.Decrypt(encryptedtext, aes.Key);
            byte[] decryptedText = System.Convert.FromBase64String(hexToASCIITB.Text);
            txtdecryptedTB.Text = Symmetric_Encrypted.Decrypt(decryptedText, aes.Key);
        }

        private void asciiToHexBt_Click(object sender, RoutedEventArgs e)
        {//covert txtencrypt from ascii to hex 
            asciiToHexTB.Text = ASCIIToHex(txtencryptedTB.Text);
        }

        private void hexToAsciiBt_Click(object sender, RoutedEventArgs e)
        {//convert txtdecrypt from hex to ascii
            hexToASCIITB.Text = HEXToASCII(asciiToHexTB.Text);
        }

        public string ASCIIToHex(string input)
        {
            StringBuilder sb = new StringBuilder();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            foreach (byte b in inputBytes)
            {
                sb.Append(string.Format("{0:x2} ", b));
            }
            return sb.ToString();
        }

        public string HEXToASCII(string input)
        {
#if false
            byte[] bb = Enumerable.Range(0, tmp.Length)
                 .Where(x => x % 2 == 0)
                 .Select(x => Convert.ToByte(tmp.Substring(x, 2), 16))
                 .ToArray();
            return System.Text.Encoding.ASCII.GetString(bb);
#else
            if(input.Length % 3 != 0)
            {
                int remind = input.Length % 3;
                if (remind == 2)
                    input += " ";
            }
            var sb = new StringBuilder();
            for (var i = 0; i < input.Length; i += 3)
            {
                var hexChar = "";
                //if (i + 3 < input.Length)
                {
                    hexChar = input.Substring(i, 3).Trim();
                    i += 3;
                    sb.Append((char)Convert.ToByte(hexChar, 16));
                }
                /*else if (i + 2 < input.Length)
                {
                    hexChar = input.Substring(i, 2).Trim();
                    i += 2;
                    sb.Append((char)Convert.ToByte(hexChar, 16));
                } */               
            }
            return sb.ToString();
#endif
        }

        private void generateRandomNum_Click(object sender, RoutedEventArgs e)
        {
            string[] readLine = File.ReadAllLines(@"c:\temp\Setting.dat");
            var index = Array.Find(readLine, element => element.StartsWith("ComPort", StringComparison.Ordinal));
            string[] data = index.Split(',');

            Random r = new Random();             
            int x = r.Next(32767);//Max range
            randomNumTb.Text = x.ToString();
            //store in HEX format
            File.WriteAllText(accessCodePath, ASCIIToHex(randomNumTb.Text));
        }

        private void binary2ASCII_Click(object sender, RoutedEventArgs e)
        {
            var data = GetBytesFromBinaryString(txtdecryptedTB.Text);
            binaryTb.Text = Encoding.ASCII.GetString(data);
        }

        public Byte[] GetBytesFromBinaryString(String input)
        {
            var list = new List<Byte>();
            var binaryList = input.Split(' ');

            for (int i = 0; i < binaryList.Length; i++)
            {
                list.Add(Convert.ToByte(binaryList[i], 2));
            }
            return list.ToArray();
        }
        public string AddHexSpace(string input)
        {
            return String.Join(" ", Regex.Matches(input, @"\d{2}")
                        .OfType<Match>()
                        .Select(m => m.Value).ToArray());
        }
        private void labelConvert_Click(object sender, RoutedEventArgs e)
        {
#if true
            int beginWith = txtdecryptedTB.Text.IndexOf('A');
            int endWith = txtdecryptedTB.Text.IndexOf('C');
            decimal addVolume = Convert.ToDecimal(txtdecryptedTB.Text.Substring(beginWith + 1, endWith - beginWith - 1), new CultureInfo("en-US"));
#else

            string tmpWord = txtdecryptedTB.Text.Substring(0, 2);
            string serialNumber = txtdecryptedTB.Text.Substring(2);
            string label = ASCIIToHex(tmpWord);
            label += AddHexSpace(Int32.Parse(serialNumber).ToString("X20"));
            binaryTb.Text = label;
#endif
        }
    }
}
