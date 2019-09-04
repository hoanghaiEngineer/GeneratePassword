 // account.Password = App.PasswordHasher.Hash(
                    // HashType.Default,
                    // PasswordGenerator.AutoGenerate(8)
                // );
using System;
using System.Collections.Generic;

namespace Cosmenist.Utility.Security
{
    public class PasswordGenerator
    {
        public static int[] Numbers = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };

        public static char[] AbcAlphabet = ABCAlphabet();

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
                    random.Next(2) == 1 ?
                        Numbers[random.Next(9)].ToString() :
                        AbcAlphabet[random.Next(AbcAlphabet.Length)].ToString()
                );
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