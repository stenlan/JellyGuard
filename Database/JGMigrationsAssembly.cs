using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Internal;
using Microsoft.Extensions.Logging;
using System.Reflection;
namespace JellyGuard.Database
{
    public class JGMigrationsAssembly : MigrationsAssembly
    {
        // private readonly Type _contextType;

        public JGMigrationsAssembly(ICurrentDbContext currentContext, IDbContextOptions options, IMigrationsIdGenerator idGenerator, IDiagnosticsLogger<DbLoggerCategory.Migrations> logger) : base(currentContext, options, idGenerator, logger)
        {
            // _contextType = currentContext.Context.GetType();
        }

        public override IReadOnlyDictionary<string, TypeInfo> Migrations
        {
            get
            {
                var baseMigrations = (SortedList<string, TypeInfo>) base.Migrations;
                
                var extra = from t in GetType().Assembly.DefinedTypes
                      where t.IsSubclassOf(typeof(Migration))
                          // && t.GetCustomAttribute<DbContextAttribute>()?.ContextType == _contextType
                      let id = t.GetCustomAttribute<MigrationAttribute>()?.Id
                      orderby id
                      select (id, t);

                Console.WriteLine("[JellyGuard] Injecting migrations...");

                foreach (var (id, t) in extra)
                {
                    baseMigrations[id] = t;
                }

                return baseMigrations;
            }
        }
    }
}
