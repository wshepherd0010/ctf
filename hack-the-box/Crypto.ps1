param([String] $opt, [String] $file, [String] $pass)
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Security.Cryptography;

    /// <summary>
    /// Crypto Utility
    /// </summary>
    public static class Crypto
    {        
        /// <summary>
        /// Main Function 
        /// Requires: option (encrypt or decrypt), file, and password
        /// </summary>
        /// <param name="args"></param>
        public static void Main(string[] args)
        {
            // Usage
            String usage = "Usage: powershell -file ./crypto.ps1 -opt encrypt|decrypt -file file -pass password";

            // Options Present
            if(args.Length.Equals(3))
            {                
                // Parameters
                String option = args[0];
                String inputFile = args[1];
                String password = args[2];

                // Run Option
                switch(option.ToLower())
                {
                    case "encrypt":
                        AES_Encrypt(inputFile, password);
                        break;
                    case "decrypt":
                        AES_Decrypt(inputFile, password);
                        break;
                    default:
                        Console.WriteLine(usage);
                        break;
                }                
            } else
                Console.WriteLine(usage);            
        }

        /// <summary>
        /// AES Encrypt
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="password"></param>
        private static void AES_Encrypt(string inputFile, string password)
        {
            //http://stackoverflow.com/questions/27645527/aes-encryption-on-large-files

            //generate random salt
            byte[] salt = GenerateRandomSalt();

            //create output file name
            FileStream fsCrypt = new FileStream(inputFile + ".aes", FileMode.Create);

            //convert password string to byte arrray
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            //Set Rijndael symmetric encryption algorithm
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;

            //http://stackoverflow.com/questions/2659214/why-do-i-need-to-use-the-rfc2898derivebytes-class-in-net-instead-of-directly
            //"What it does is repeatedly hash the user password along with the salt." High iteration counts.
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            //Cipher modes: http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
            AES.Mode = CipherMode.CFB;

            //write salt to the begining of the output file, so in this case can be random every time
            fsCrypt.Write(salt, 0, salt.Length);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    //Application.DoEvents(); // -> for responsive GUI, using Task will be better!
                    cs.Write(buffer, 0, read);
                }

                //close up
                fsIn.Close();

            }
            catch (Exception ex)
            {
                //Debug.WriteLine("Error: " + ex.Message);
                Console.WriteLine(ex.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
                File.Delete(inputFile);
            }
        }

        /// <summary>
        /// AES Decrypt
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="password"></param>
        private static void AES_Decrypt(string inputFile, string password)
        {
            //todo:
            // - create error message on wrong password
            // - on cancel: close and delete file
            // - on wrong password: close and delete file!
            // - create a better filen name
            // - could be check md5 hash on the files but it make this slow

            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[32];

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

            FileStream fsOut = new FileStream(inputFile + ".decrypted", FileMode.Create);

            int read;
            byte[] buffer = new byte[1048576];

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    //Application.DoEvents();
                    fsOut.Write(buffer, 0, read);
                }
            }
            catch (System.Security.Cryptography.CryptographicException ex_CryptographicException)
            {
                Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();                

                File.Move(inputFile+".decrypted", inputFile.Remove(inputFile.Length - 4));
                File.Delete(inputFile);
            }
        }

        /// <summary>
        /// Generate Salt
        /// </summary>
        /// <returns></returns>
        public static byte[] GenerateRandomSalt()
        {
            //Source: http://www.dotnetperls.com/rngcryptoserviceprovider
            byte[] data = new byte[32];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                // Ten iterations.
                for (int i = 0; i < 10; i++)
                {
                    // Fill buffer.
                    rng.GetBytes(data);
                }
            }
            return data;
        }
    }
"@

$params = @($opt, $file, $pass)
[Crypto]::Main($params)