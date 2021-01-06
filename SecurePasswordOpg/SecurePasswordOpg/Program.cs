using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurePasswordOpg
{
    class Program
    {
        static void Main(string[] args)
        {
            DalManager dalManager = new DalManager();
            Console.WriteLine("Please enter your username and password to login");
            Console.WriteLine("(1) Create an account");
            Console.WriteLine("(2) Login");
            int input = int.Parse(Console.ReadLine());
            while (true)
            {

                switch (input)
                {
                    case 1:
                        Console.WriteLine("Write wanted username:");
                        string newUsername = Console.ReadLine();
                        Console.WriteLine("Write wanted password:");
                        string newPassword = Console.ReadLine();
                        dalManager.GenerateSalt();
                        dalManager.StoreHashedPassword(newUsername, dalManager.CreateHashedPassword(newPassword));
                        Console.WriteLine("user created");
                        break;
                    case 2:
                        Console.WriteLine("Username:");
                        string loginUsername = Console.ReadLine();
                        Console.WriteLine("Password:");
                        string loginPassword = Console.ReadLine();
                        if (dalManager.ValidatePassword(loginPassword, loginUsername) == true)
                        {
                            Console.WriteLine("access granted");
                        }
                        else
                        {
                            Console.WriteLine("access denied");
                        }

                        break;
                    default:
                        Console.WriteLine("Wrong input");
                        break;
                }
            }
        }
    }
}
