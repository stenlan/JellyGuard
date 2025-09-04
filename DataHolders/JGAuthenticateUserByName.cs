using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JellyGuard.DataHolders
{
    public class JGAuthenticateUserByName : Jellyfin.Api.Models.UserDtos.AuthenticateUserByName
    {
        /// <summary>
        /// Gets or sets the time-based one time password.
        /// </summary>
        public string? TOTP { get; set; }
    }
}
