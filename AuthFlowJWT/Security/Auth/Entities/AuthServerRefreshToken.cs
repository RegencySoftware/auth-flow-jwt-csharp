using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthFlow.Security.Auth.Entities
{
    class AuthServerRefreshToken
    {
        public string refreshToken { get; set; }
        public string userName { get; set; }
    }
}
