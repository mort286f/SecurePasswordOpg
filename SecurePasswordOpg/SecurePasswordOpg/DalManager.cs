using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurePasswordOpg
{
    class DalManager
    {
        private static string connString = "Server=(localdb)\\MSSQLLocaldb; Database=SecurePassword; Integrated Security=True";

        private static string salt;

        public void GenerateSalt()
        {
            using (var randomGenerator = new RNGCryptoServiceProvider())
            {
                byte[] buff = new byte[8];
                randomGenerator.GetBytes(buff);

                salt = Convert.ToBase64String(buff);
            }
        }

        public string CreateHashedPassword(string passwrd)
        {
            byte[] pwdWithSalt = Encoding.ASCII.GetBytes(string.Concat(passwrd, salt));
            using (var sha256 = SHA256.Create())
            {
                return Convert.ToBase64String(sha256.ComputeHash(pwdWithSalt));
            }
        }

        public void StoreHashedPassword(string username, string hashedPassword)
        {
            using (SqlConnection conn = new SqlConnection(connString))
            {
                conn.Open();
                SqlCommand cmd = new SqlCommand("INSERT INTO Users VALUES (@username, @password, @salt)", conn);
                cmd.Parameters.Add(new SqlParameter("@username", username));
                cmd.Parameters.Add(new SqlParameter("@password", hashedPassword));
                cmd.Parameters.Add(new SqlParameter("@salt", salt));
                cmd.ExecuteNonQuery();
            }
        }

        public static string GetSaltFromDatabase(string username)
        {
            string returnedSalt = "";
            using (SqlConnection conn = new SqlConnection(connString))
            {
                conn.Open();
                SqlCommand cmd = new SqlCommand("SELECT Salt FROM Users WHERE Username = @username", conn);
                cmd.Parameters.Add(new SqlParameter("@username", username));
                SqlDataReader rdr = cmd.ExecuteReader();
                while (rdr.Read())
                {
                    returnedSalt = (string)rdr[0];
                }
            }
            return returnedSalt;
        }

        public static string GetHashedPasswordFromDataBase(string username)
        {
            string returnedPwd = "";
            using (SqlConnection conn = new SqlConnection(connString))
            {
                conn.Open();
                SqlCommand cmd = new SqlCommand("SELECT Password FROM Users WHERE Username = @username", conn);
                cmd.Parameters.Add(new SqlParameter("@username", username));
                SqlDataReader rdr = cmd.ExecuteReader();
                while (rdr.Read())
                {
                    returnedPwd = (string)rdr[0];
                }
            }
            return returnedPwd;
        }
        public bool ValidatePassword(string password, string username)
        {
            string tempPwd = "";
            byte[] pwdWithSaltFromDB = Encoding.ASCII.GetBytes(string.Concat(password, GetSaltFromDatabase(username)));
            using (var sha256 = SHA256.Create())
            {
                tempPwd = Convert.ToBase64String(sha256.ComputeHash(pwdWithSaltFromDB));
            }
            if (tempPwd == GetHashedPasswordFromDataBase(username))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

    }
}
