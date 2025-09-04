using Jellyfin.Server.Implementations;
using JellyGuard.Database.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JellyGuard.Database
{
    public static class JellyfinDbContextExtensions
    {
        public static DbSet<AuthenticationProviderData> AuthenticationProviderDatas(this JellyfinDbContext context)
        {
            return context.Set<AuthenticationProviderData>();
        }

        public static DbSet<UserAuthenticationProviderData> UserAuthenticationProviderDatas(this JellyfinDbContext context)
        {
            return context.Set<UserAuthenticationProviderData>();
        }
    }
}
