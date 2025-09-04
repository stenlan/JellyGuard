using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace JellyGuard.Database
{
    public class JGModelCustomizer : RelationalModelCustomizer
    {
        public JGModelCustomizer(ModelCustomizerDependencies dependencies) : base(dependencies)
        {
        }

        public override void Customize(ModelBuilder modelBuilder, DbContext context)
        {
            base.Customize(modelBuilder, context);
            modelBuilder.ApplyConfigurationsFromAssembly(GetType().Assembly);
        }
    }
}
