using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Autofac.Util;
using LetsEncryptAzureCdn.Helpers;
using LetsEncryptAzureCdn.Models;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Supertext.Base.Net.Mail;

namespace LetsEncryptAzureCdn
{
    public class ApplyOrRenewCertificate : Disposable
    {
        private const int ExpirationInDays = 30;
        private readonly ILogger _logger;
        private readonly IMailService _mailService;

        public ApplyOrRenewCertificate(ILogger logger, IMailService mailService)
        {
            _logger = logger;
            _mailService = mailService;
        }

        [FunctionName("ApplyOrRenewCertificate")]
        public async Task Run([TimerTrigger("0 30 2 * * *")] TimerInfo myTimer, ExecutionContext executionContext)
        {
            try
            {
                await ExecuteApplyOrRenewCertificatesAsync(executionContext).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                _logger.LogError(e, $"Exception occurred in function {nameof(ApplyOrRenewCertificate)}");
                await SendErrorMailAsync(e).ConfigureAwait(false);
                throw;
            }
        }

        private async Task SendErrorMailAsync(Exception e)
        {
            try
            {
                var email = new EmailInfo($"Supersystem CDN: Error in {nameof(ApplyOrRenewCertificate)}",
                                          $"{e.Message}{Environment.NewLine}{e.StackTrace}{Environment.NewLine}",
                                          new PersonInfo($"Az func {nameof(ApplyOrRenewCertificate)}", "development@supertext.com"),
                                          new PersonInfo($"Supertext Developers", "development@supertext.com"));
                await _mailService.SendAsHtmlAsync(email).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, $"Exception occurred while sending an error mail {nameof(SendErrorMailAsync)}");
                throw;
            }
        }

        private async Task ExecuteApplyOrRenewCertificatesAsync(ExecutionContext executionContext)
        {
            _logger.LogInformation($"C# Timer trigger function executed at: {DateTime.Now}");

            var config = new ConfigurationBuilder()
                         .SetBasePath(executionContext.FunctionAppDirectory)
                         .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true)
                         .AddEnvironmentVariables()
                         .Build();

            var subscriptionId = Environment.GetEnvironmentVariable("SubscriptionId") ?? config.GetSection("SubscriptionId").Value;

            _logger.LogInformation($"Subscription id: {subscriptionId}");

            var certificateDetails = new List<CertificateRenewalInputModel>();
            config.GetSection("CertificateDetails").Bind(certificateDetails);

            foreach (var certifcate in certificateDetails)
            {
                try
                {
                    await CreateCertificateAsync(certifcate, subscriptionId).ConfigureAwait(false);
                    _logger.LogInformation("************************************");
                }
                catch (Exception e)
                {
                    _logger.LogError(e, "Creating certificate failed.");
                    throw;
                }
            }
        }

        private async Task CreateCertificateAsync(CertificateRenewalInputModel certifcate, string subscriptionId)
        {
            _logger.LogInformation($"Processing certificate - {certifcate.DomainName}");
            var acmeHelper = new AcmeHelper(_logger);
            var certificateHelper = new KeyVaultCertificateHelper(certifcate.KeyVaultName);

            await InitAcmeAwait(_logger, certifcate, acmeHelper).ConfigureAwait(false);

            var domainName = certifcate.DomainName;
            if (domainName.StartsWith("*"))
            {
                domainName = domainName.Substring(1);
            }

            _logger.LogInformation($"Calculated domain name is {domainName}");

            var keyVaultCertificateName = domainName.Replace(".", "");
            _logger.LogInformation($"Getting expiry for {keyVaultCertificateName} in Key Vault certifictes");
            var certificateExpiry = await certificateHelper.GetCertificateExpiryAsync(keyVaultCertificateName).ConfigureAwait(false);
            if (certificateExpiry.HasValue && certificateExpiry.Value.Subtract(DateTime.UtcNow).TotalDays > ExpirationInDays)
            {
                _logger.LogInformation("No certificates to renew.");
                return;
            }

            _logger.LogInformation("Creating order for certificates");

            await acmeHelper.CreateOrderAsync(certifcate.DomainName).ConfigureAwait(false);
            _logger.LogInformation("Authorization created");

            await FetchAndCreateDnsRecordsAsync(_logger, subscriptionId, certifcate, acmeHelper, domainName).ConfigureAwait(false);
            _logger.LogInformation("Validating DNS challenge");

            await acmeHelper.ValidateDnsAuthorizationAsync().ConfigureAwait(false);
            _logger.LogInformation("Challenge validated");

            var password = Guid.NewGuid().ToString();
            var pfx = await acmeHelper.GetPfxCertificateAsync(password,
                                                              certifcate.CertificateCountryName,
                                                              certifcate.CertificateState,
                                                              certifcate.CertificateLocality,
                                                              certifcate.CertificateOrganization,
                                                              certifcate.CertificateOrganizationUnit,
                                                              certifcate.DomainName,
                                                              domainName)
                                      .ConfigureAwait(false);
            _logger.LogInformation("Certificate built");

            (string certificateName, string certificateVerison) = await certificateHelper.ImportCertificate(keyVaultCertificateName, pfx, password);
            _logger.LogInformation("Certificate imported");

            var cdnHelper = new CdnHelper(subscriptionId);
            await cdnHelper.EnableHttpsForCustomDomainAsync(certifcate.CdnResourceGroup,
                                                       certifcate.CdnProfileName,
                                                       certifcate.CdnEndpointName,
                                                       certifcate.CdnCustomDomainName,
                                                       certificateName,
                                                       certificateVerison,
                                                       certifcate.KeyVaultName)
                           .ConfigureAwait(false);
            _logger.LogInformation("HTTPS enabling started");
        }

        private static async Task FetchAndCreateDnsRecordsAsync(ILogger log, string subscriptionId, CertificateRenewalInputModel certifcate, AcmeHelper acmeHelper, string domainName)
        {
            var dnsHelper = new DnsHelper(subscriptionId);
            log.LogInformation("Fetching DNS authorization");
            var dnsText = await acmeHelper.GetDnsAuthorizationTextAsync();
            var dnsName = ("_acme-challenge." + domainName).Replace("." + certifcate.DnsZoneName, "").Trim();
            log.LogInformation($"Got DNS challenge {dnsText} for {dnsName}");
            await CreateDnsTxtRecordsIfNecessaryAsync(log, certifcate, dnsHelper, dnsText, dnsName).ConfigureAwait(false);
            log.LogInformation("Waiting 60 seconds for DNS propagation");
            await Task.Delay(60 * 1000).ConfigureAwait(false);
        }

        private static async Task InitAcmeAwait(ILogger log, CertificateRenewalInputModel certifcate, AcmeHelper acmeHelper)
        {
            var secretHelper = new KeyVaultSecretHelper(certifcate.KeyVaultName);
            var acmeAccountPem = await secretHelper.GetSecretAsync("AcmeAccountKeyPem").ConfigureAwait(false);
            if (String.IsNullOrWhiteSpace(acmeAccountPem))
            {
                log.LogInformation("Acme Account not found.");
                var pem = await acmeHelper.InitWithNewAccountAsync(Environment.GetEnvironmentVariable("AcmeAccountEmail"));
                log.LogInformation("Acme account created");
                await secretHelper.SetSecretAsync("AcmeAccountKeyPem", pem).ConfigureAwait(false);
                log.LogInformation("Secret uploaded to key vault");
            }
            else
            {
                acmeHelper.InitWithExistingAccount(acmeAccountPem);
            }
        }

        private static async Task CreateDnsTxtRecordsIfNecessaryAsync(ILogger log, CertificateRenewalInputModel certifcate, DnsHelper dnsHelper, string dnsText, string dnsName)
        {
            var txtRecords = await dnsHelper.FetchTxtRecordsAsync(certifcate.DnsZoneResourceGroup, certifcate.DnsZoneName, dnsName).ConfigureAwait(false);
            if (txtRecords == null || !txtRecords.Contains(dnsText))
            {
                await dnsHelper.CreateTxtRecordAsync(certifcate.DnsZoneResourceGroup, certifcate.DnsZoneName, dnsName, dnsText).ConfigureAwait(false);
                log.LogInformation("Created DNS TXT records");
            }
        }
    }
}
