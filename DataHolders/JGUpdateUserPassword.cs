using Jellyfin.Api.Models.UserDtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JellyGuard.DataHolders
{
    /// <summary>
    /// The JellyGuard update user password request body.
    /// </summary>
    public class JGUpdateUserPassword : UpdateUserPassword
    {
        /// <summary>
        /// Gets or sets the time-based one-time password.
        /// </summary>
        public string? TOTP { get; set; }
    }
}
