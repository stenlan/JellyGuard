using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JellyGuard.DataHolders
{
    public class JGQuickConnectResult : MediaBrowser.Model.QuickConnect.QuickConnectResult
    {
        public JGQuickConnectResult(string secret, string code, DateTime dateAdded, string deviceId, string deviceName, string appName, string appVersion) : base(secret, code, dateAdded, deviceId, deviceName, appName, appVersion)
        {
        }

        /// <summary>
        /// Gets or sets a value indicating an optional UserId of a user whom this request is authorized to authenticate as.
        /// </summary>
        public Guid? UserId { get; set; }
    }
}
