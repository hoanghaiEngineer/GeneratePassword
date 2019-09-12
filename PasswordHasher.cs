using System;
using System.Collections.Generic;
using System.Text;
using System.Web.Helpers;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace DispositionAppWeb.Services
{
    public enum HashType
    {
        Default,
        SHA256,
        SHA1
    }
    public class PasswordHasher
    {
        public PasswordHasher(int generateSalt)
        {
            Crypto.GenerateSalt(generateSalt);
        }

        public string Hash(HashType hashType, string password)
        {
            switch (hashType)
            {
                case HashType.SHA1:
                    return Crypto.Hash(Encoding.UTF8.GetBytes(password), algorithm: "sha1");
                case HashType.SHA256:
                    return Crypto.Hash(Encoding.UTF8.GetBytes(password), algorithm: "sha256");
                default:
                    return Crypto.HashPassword(password);
            }
        }

        private bool SHAVerify(HashType hashType, string hashedPassword, string comparePassword)
        {
            return StringComparer.CurrentCulture
                       .Compare(
                           hashedPassword,
                           this.Hash(hashType, comparePassword)
                       ) == 0;
        }

        public bool Verify(HashType hashType, string hashedPassword, string passwordCompare)
        {
            switch (hashType)
            {
                case HashType.Default:
                    return Crypto.VerifyHashedPassword(hashedPassword, passwordCompare);
                default:
                    return this.SHAVerify(hashType, hashedPassword, passwordCompare);
            }
        }

        public string Decrypt_PasswordHash(string passwordHash)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(passwordHash);
            var result = Encoding.UTF8.GetString(bytes);
            return result;
        }
    }
    class PasswordPolicy
    {
        private static int minimun_length = 8;
        private static int maximun_length = 16;

        public static bool IsValid(string password)
        {
            if (password.Length < minimun_length || password.Length > maximun_length)
                return false;
            if (NonAlphaCount(password) < 1)
                return false;
            if (NumericCount(password) < 1)
                return false;
            if (AlphaCount(password) < 1)
                return false;
            return true;
        }

        private static int UpperCaseCount(string Password)
        {
            return Regex.Matches(Password, "[A-Z]").Count;
        }

        private static int LowerCaseCount(string Password)
        {
            return Regex.Matches(Password, "[a-z]").Count;
        }
        private static int NumericCount(string Password)
        {
            return Regex.Matches(Password, "[0-9]").Count;
        }
        private static int NonAlphaCount(string Password)
        {
            return Regex.Matches(Password, @"[^0-9a-zA-Z\._]").Count;
        }
        private static int AlphaCount(string Password)
        {
            return Regex.Matches(Password, @"[a-zA-Z]").Count;
        }
    }

    public class PasswordGenerator
    {
        public static int[] Numbers = {1, 2, 3, 4, 5, 6, 7, 8, 9};
        public static char[] AbcAlphabet = ABCAlphabet();
        public static char[] NonAbcAlphabet = {'@', '+', '=', '/', '>', '<', '!', '*', '?', '-', '#', '%', '&'};

        /// <summary>
        /// auto generate a key text
        /// </summary>
        /// <param name="length">size of key text</param>
        /// <returns>key text</returns>
        public static string AutoGenerate(int length)
        {
            string keys = string.Empty;
            var random = new Random();
            while (string.IsNullOrEmpty(keys) || keys.Length < length)
            {
                /* when random tiket =1
                  *      select a random number
                  *  else
                  *      select a random abc alphabet
                  */
                keys = keys.Insert(0,
                    random.Next(2) == 1
                        ? Numbers[random.Next(9)].ToString()
                        : AbcAlphabet[random.Next(AbcAlphabet.Length)].ToString()
                        );
                keys = keys.Insert(keys.Length -1, NonAbcAlphabet[random.Next(NonAbcAlphabet.Length)].ToString());
            }

            return keys;
        }

        private static char[] ABCAlphabet()
        {
            List<char> alphabet = new List<char>();
            for (char i = 'A'; i <= 'Z'; i++)
            {
                alphabet.Add(i);
            }
            return alphabet.ToArray();
        }
    }
}