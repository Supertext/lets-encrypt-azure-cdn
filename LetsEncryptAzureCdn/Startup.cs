using System;
using Autofac;
using Autofac.Extensions.DependencyInjection.AzureFunctions;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Supertext.Base.Core.Configuration;
using Supertext.Base.Net;
using Supertext.Base.Net.Mail;
using Supertext.Base.Security.Configuration;

[assembly: FunctionsStartup(typeof(LetsEncryptAzureCdn.Startup))]
namespace LetsEncryptAzureCdn
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            try
            {
                builder
                    .UseAppSettings(config => config.ConfigureConfigWithKeyVaultSecrets())
                    .UseAutofacServiceProviderFactory(ConfigureContainer);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw new Exception($"{e.Message}{Environment.NewLine}{e.StackTrace}{Environment.NewLine}", e);
            }
        }

        private void ConfigureContainer(ContainerBuilder builder)
        {
            builder.RegisterModule<NetModule>();

            builder.RegisterAllConfigurationsInAssembly(typeof(MailServiceConfig).Assembly);

            // Register all functions that resides in a given namespace
            // The function class itself will be created using autofac
            builder
                .RegisterAssemblyTypes(typeof(Startup).Assembly)
                .InNamespace(nameof(LetsEncryptAzureCdn))
                .AsSelf() // Azure Functions core code resolves a function class by itself.
                .InstancePerTriggerRequest(); // This will scope nested dependencies to each function execution
        }
    }
}