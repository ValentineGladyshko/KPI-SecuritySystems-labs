using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(SecuritySystemLab1.Startup))]
namespace SecuritySystemLab1
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
