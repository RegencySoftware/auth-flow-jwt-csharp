using AuthFlow.Security.Auth.Entities;
using System;
using System.Runtime.Caching;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.ServiceModel.Security.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AuthFlowJWT.Security.Auth
{
    public class JSONWebTokens
    {
        private string _issuer { get; set; }
        private string _secrete { get; set; }
        private string _audience { get; set; }

        private int _tokenLifeMinutes { get; set; }
        private int _refreshTokenLifeMinutes { get; set; }

        /// <summary>
        /// Pass the Secrete for JWT Encryption & Auidence key (GUID for vendor)
        /// </summary>
        /// <param name="audience">The Client</param>
        /// <param name="secrete">The Secrete Key</param>
        public JSONWebTokens (string audience, string secrete)
        {
            _issuer = "mydomain.com";
            _secrete = secrete;
            _audience = audience;

            //Set the lifetime of the JWT and Refresh Token
            _tokenLifeMinutes = 20;
            _refreshTokenLifeMinutes = 30;
        }
        /// <summary>
        /// Create a JWT for a user - After Authtenicated
        /// </summary>
        /// <param name="userName">User Name</param>
        /// <returns>string</returns>
        public AuthServerJWT CreateJWT(string userName)
        {
            //contains both the JWT and Refresh Token
            var authServerJWT = new AuthServerJWT();
            authServerJWT.hasError = false;
            authServerJWT.errorMsg = string.Empty;

            var secKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.Default.GetBytes(_secrete));
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                secKey,
                SecurityAlgorithms.HmacSha256Signature);
                  
            //Setup date now and expiration date
            //DateTime centuryBegin = new DateTime(1970, 1, 1);
            //var exp = new TimeSpan(DateTime.Now.AddMinutes(20).Ticks - centuryBegin.Ticks).TotalSeconds;
            //var now = new TimeSpan(DateTime.Now.Ticks - centuryBegin.Ticks).TotalSeconds;
                     
            var now = DateTimeOffset.Now.ToUnixTimeSeconds();
            var exp =  DateTimeOffset.Now.AddMinutes(20).ToUnixTimeSeconds();

            //Setup the header
            var header = new JwtHeader(signingCredentials);

            List<string> Groups = new List<string>();

            var userADGroups = AuthFlowJWT.Security.Auth.ActiveDirectory.GetADGroups(userName);           

            var payload = new JwtPayload
            {
                    {"iss", _issuer},
                    {"aud", _audience},
                    {"iat", now},
                    {"exp", exp},
                    {"groups", userADGroups}
            };

            //Create the JWT
            var secToken = new JwtSecurityToken(header, payload);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(secToken);
            authServerJWT.jsonWebToken = jwt;

            //Generate the Refresh Token
            authServerJWT.refreshToken = GenerateRefreshToken(userName);

            return authServerJWT;
        }
        /// <summary>
        /// Refresh Token is a GUID + UserID. An instance of the class "AuthServerRefreshToken" 
        /// will be added to the memory cache for 10 minutes longer than the JWT.
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        private string GenerateRefreshToken(string userName)
        {
            //Create a refesh token + user name to store in the cache            
            var refreshTokenForCache = new AuthServerRefreshToken();
            refreshTokenForCache.userName = userName;
            refreshTokenForCache.refreshToken = new Guid().ToString("N");

            //Did this just for documentation sake, the key is the token
            var cacheKeyRefreshToken = refreshTokenForCache.refreshToken;

            //Add to Cache for x minutes
            CacheItemPolicy cachePolicy = new CacheItemPolicy();
            ObjectCache cache = MemoryCache.Default;
            cachePolicy.AbsoluteExpiration = DateTimeOffset.Now.AddSeconds((_refreshTokenLifeMinutes * 60));
            cache.Set(cacheKeyRefreshToken, refreshTokenForCache, cachePolicy);

            return cacheKeyRefreshToken;
        }
        /// <summary>
        /// Verify the signature of a JWT
        /// </summary>
        /// <param name="jwt">JWT</param>
        /// <param name="audience">The Client</param>
        /// <param name="secrete">The Secrete Key</param>
        /// <returns></returns>
        public bool VerifyJWTSignature(string jwt)
        {
            bool valid = true;

            var secKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.Default.GetBytes(_secrete));

            var validationParameters = new TokenValidationParameters()
            {
                ValidateAudience = true,
                ValidAudience = _audience,
                ValidateIssuer = true,
                ValidIssuer = _issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = secKey,
                RequireExpirationTime = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            try
            {
                SecurityToken mytoken = new JwtSecurityToken();
                var myTokenHandler = new JwtSecurityTokenHandler();
                var myPrincipal = myTokenHandler.ValidateToken(jwt, validationParameters, out mytoken);
            }
            catch (Exception ex)
            {
                valid = false;
            }

            return valid;
        }
        /// <summary>
        /// Renew the token by passing the JWT. If the renewal token is still valid a
        /// new JWT will be created.
        /// </summary>
        /// <param name="jwt">JWT</param>
        /// <returns></returns>
        public AuthServerJWT RenewJWT(string refreshToken)
        {
            var jwtRenewed = string.Empty;

            ObjectCache cache = MemoryCache.Default;
            var cacheRenewalJWT = (AuthServerRefreshToken)cache[refreshToken];

            var jwt = new AuthServerJWT();

            //If no refresh token is found, it means it expired. 
            if (cacheRenewalJWT == null)
            {
                jwt.jsonWebToken = string.Empty;
                jwt.refreshToken = string.Empty;                
                jwt.hasError = true;
                jwt.errorMsg = "Refresh Token Expired";
                return jwt;
            }

            //The refresh token is valid, return a new JWT
            jwt = CreateJWT(cacheRenewalJWT.userName);

            return jwt;
        }

        /// <summary>
        /// Convert Secrete to Bytes
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        private byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;

        }
    }
}
