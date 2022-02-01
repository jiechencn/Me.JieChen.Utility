using Microsoft.Identity.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace Me.JieChen.Utility.ClientAssertationClient;

public class Program
{
    public static void Main(string[] args)
    {
        Console.WriteLine("A simple tool to get client_assertion from certficate which is used to be authenticated by AAD \nRead: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials");
        Console.Write("\nTenantId: ");
        string? tenantId = Console.ReadLine()?.Trim();

        Console.Write("ClientAppId: ");
        string? clientAppId = Console.ReadLine()?.Trim();

        Console.Write("Certificate Path (A pfx format certificate file which includes private key): ");
        string? certPath = Console.ReadLine()?.Trim();

        Console.Write("Certificate Password (a passord used to protect the private key when the certificate was exported): ");
        string? certPwd = Console.ReadLine()?.Trim();

        CertificateDescription certificateDescription = CertificateDescription.FromPath(certPath!, certPwd);
        DefaultCertificateLoader defaultCertificateLoader = new DefaultCertificateLoader();
        defaultCertificateLoader.LoadIfNeeded(certificateDescription);
        X509Certificate2? certificate = certificateDescription.Certificate;
        string client_assertion = GetSignedClientAssertionAlt(certificate, tenantId!, clientAppId!);

        Console.WriteLine("\nclient_assertion:\n");
        Console.WriteLine(client_assertion + "\n");
        Console.Read();
    }

    static string GetSignedClientAssertionAlt(X509Certificate2? certificate, string tenantId, string clientAppId)
    {
        
        string aud = $"https://login.microsoftonline.com/{tenantId}/v2.0";

        var claims = new Dictionary<string, object>()
            {
                { "aud", aud },
                { "iss", clientAppId },
                { "jti", Guid.NewGuid().ToString() },
                { "sub", clientAppId }
            };

        var securityTokenDescriptor = new SecurityTokenDescriptor
        {
            Claims = claims,
            SigningCredentials = new X509SigningCredentials(certificate)
        };

        var handler = new JsonWebTokenHandler();
        var signedClientAssertion = handler.CreateToken(securityTokenDescriptor);

        return signedClientAssertion;
    }
}