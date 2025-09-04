using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;

namespace JellyGuard
{
    public class JellyGuardPlugin : BasePlugin<PluginConfiguration>
    {
        private ILogger<JellyGuardPlugin> _logger;
        public override string Name => "JellyGuard";

        public override Guid Id => Guid.Parse("ff503eb2-8815-44f9-91ab-b03e90daa327");

        public JellyGuardPlugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer, ILogger<JellyGuardPlugin> logger) : base(applicationPaths, xmlSerializer) {
            _logger = logger;
            _logger.LogInformation("Initialized");
        }
    }
}
