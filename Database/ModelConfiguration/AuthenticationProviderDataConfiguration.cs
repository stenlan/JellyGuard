using Jellyfin.Data.Entities;
using JellyGuard.Database.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace JellyGuard.Database.ModelConfiguration
{
    /// <summary>
    /// Additional FluentAPI configuration for the User entity.
    /// </summary>
    public class AuthenticationProviderDataConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            builder
                .HasMany<AuthenticationProviderData>(/* u => u.AuthenticationProviderDatas */)
                .WithMany(d => d.Users)
                .UsingEntity<UserAuthenticationProviderData>(
                    r => r.HasOne<AuthenticationProviderData>().WithMany(d => d.UserAuthenticationProviderDatas).HasForeignKey("AuthenticationProviderId"),
                    l => l.HasOne<User>().WithMany(/* u => u.UserAuthenticationProviderDatas */).HasForeignKey("UserId"));
        }
    }
}
