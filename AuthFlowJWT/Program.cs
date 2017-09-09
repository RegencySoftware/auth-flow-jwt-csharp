using AuthFlow.Security.Auth.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;

namespace AuthFlowJWT
{
    class Program
    {
        static string _domain = "your-domain-here.com";

        static Dictionary<string, int> adExcludeGroups = new Dictionary<string, int>();

        //!!!! UPDATE WITH YOUR LOGIN INFO !!!!
        static string _userName = "youruserid here";
        static string _password = "";

        static string _secrete = "d0c012e405aa4a079d31e03047724550";
        static string _audience = "65f2bace503f45f1be98a5e5dd7cefdd";

        static void Main(string[] args)
        {
            //Test User Login
            //TestUserLogin();

            //Test Get JWT for a user - This will also test renewing the JWT
            TestCreateJWT();

            Console.ReadLine();
        }
        /// <summary>
        /// Test user Auth
        /// </summary>
        private static void TestUserLogin()
        {
            if (_password == string.Empty)
            {
                Console.WriteLine("\nEnter your User ID and Password!");
            }

            var validLogin = AuthFlowJWT.Security.Auth.ActiveDirectory.AutenticateUser(_userName, _password);

            if (validLogin)
            {
                Console.WriteLine("\nSuccess - User Authenticated");
            }
            else
            {
                Console.WriteLine("\nFailed - User Authenticated");
            }
        }
        /// <summary>
        /// Get JWT
        /// </summary>
        /// <returns></returns>
        private static void TestCreateJWT()
        {
            var jwtSecurity = new AuthFlowJWT.Security.Auth.JSONWebTokens(_audience, _secrete);
                     
            //1. Get a new JWT
            var jwtAuthServer = jwtSecurity.CreateJWT(_userName);
            WriteJWTToConsole("----NEW JWT----", jwtAuthServer);

            //2. Verify Signature: Simulate the client passing a JWT and verify the signature
            var jwtVerfied = jwtSecurity.VerifyJWTSignature(jwtAuthServer.jsonWebToken);
            if (jwtVerfied)
            {
                Console.WriteLine("\nSuccess - Signature is Valid");
            }
            else
            {
                Console.WriteLine("\nFailed - Signature is Not Valid");
            }

            //3. Rewnew Token: Simulate the client passing a JWT and renew the expiration date
            var renewedJWT = jwtSecurity.RenewJWT(jwtAuthServer.refreshToken);

            if (renewedJWT.hasError == false)
            {
                WriteJWTToConsole("----Renewed JWT----", renewedJWT);
            }
            else
            {
                Console.WriteLine("\nRenewal Faild");
                Console.WriteLine("\n" + jwtAuthServer.errorMsg);
            }
        }
        private static void WriteJWTToConsole(string msg, AuthServerJWT jwt)
        {
            Console.WriteLine("\n" + msg + "\n");
            Console.WriteLine(jwt.jsonWebToken);
        }
            

    }
}
