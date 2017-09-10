using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;

namespace AuthFlowJWT.Security.Auth
{
    public static class ActiveDirectory
    {
        private const string _domain = "youradhere.com";
        /// <summary>
        /// Login the user
        /// </summary>
        /// <param name="userName">UserName</param>
        /// <param name="password">Password</param>
        /// <returns>bool</returns>
        public static bool AutenticateUser(string userName, string password)
        {
            bool isValid = false;

            using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, _domain))
            {
                // validate the credentials
                isValid = pc.ValidateCredentials(userName, password);
            }

            return isValid;
        }
        /// <summary>
        /// Get User AD Groups for JWT
        /// </summary>
        /// <param name="userName">userName</param>
        /// <returns>List of groups</returns>
        public static List<string> GetADGroups(string userName)
        {
            List<string> userADGroups = new List<string>();
            userADGroups.Add("Information Tech");
            userADGroups.Add("App Dev Team");

            return userADGroups;

            //-------------------------------------------------------------
            //Continue below if you are connecting to an active directory

            UserPrincipal user = UserPrincipal.FindByIdentity(new PrincipalContext(ContextType.Domain, _domain), IdentityType.SamAccountName, userName);

            if (user == null) return userADGroups;

            foreach (GroupPrincipal group in user.GetGroups())
            {
                var GroupName = group.Name.ToLower();
                if (IncludeGroupsForJWT(GroupName)) userADGroups.Add(GroupName);
            }

            var userStorted = userADGroups.OrderBy(q => q).ToList();
            return userStorted;
        }
        /// <summary>
        /// Only include a select list of groups for JWT
        /// </summary>
        private static bool IncludeGroupsForJWT(string groupName)
        {
            groupName = groupName.ToLower();
          
            //What CSC the user is in 
            if (groupName.Contains("team")) return true;
            if (groupName.Contains("staff")) return true;

            return false;
        }

    }
}
