using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthFlow.Security.Auth.Entities
{
    public class AuthServerJWT
    {
        public string jsonWebToken { get; set; }
        public string refreshToken { get; set; }
        public bool hasError { get; set; }
        public string errorMsg { get; set; }
    }
}
