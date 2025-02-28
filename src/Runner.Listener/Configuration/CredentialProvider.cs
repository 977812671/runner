using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using GitHub.Services.Common;
using GitHub.Services.WebApi.Jwt;
using GitHub.Runner.Common;
using GitHub.Runner.Sdk;
using GitHub.Services.OAuth;

namespace GitHub.Runner.Listener.Configuration
{
    public interface ICredentialProvider
    {
        bool RequireInteractive { get; }
        GitHub.Runner.Common.CredentialData CredentialData { get; set; }
        GitHub.Services.Common.VssCredentials GetVssCredentials(IHostContext context);
        void EnsureCredential(IHostContext context, CommandSettings command, string serverUrl);
    }

    public abstract class CredentialProvider : ICredentialProvider
    {
        public CredentialProvider(string scheme)
        {
            CredentialData = new GitHub.Runner.Common.CredentialData();
            CredentialData.Scheme = scheme;
        }

        public virtual bool RequireInteractive => false;
        public GitHub.Runner.Common.CredentialData CredentialData { get; set; }

        public abstract GitHub.Services.Common.VssCredentials GetVssCredentials(IHostContext context);
        public abstract void EnsureCredential(IHostContext context, CommandSettings command, string serverUrl);
    }

    public sealed class OAuthAccessTokenCredential : CredentialProvider
    {
        public OAuthAccessTokenCredential() : base(Constants.Configuration.OAuthAccessToken) { }

        public override GitHub.Services.Common.VssCredentials GetVssCredentials(IHostContext context)
        {
            ArgUtil.NotNull(context, nameof(context));
            Tracing trace = context.GetTrace(nameof(OAuthAccessTokenCredential));
            trace.Info(nameof(GetVssCredentials));
            Console.WriteLine("GetVssCredentials called"); // 验证输出

            string token;
            if (!CredentialData.Data.TryGetValue(Constants.Runner.CommandLine.Args.Token, out token))
            {
                token = null;
            }

            if (string.IsNullOrEmpty(token))
            {
                trace.Error("Token is null or empty");
                Console.WriteLine("Error: Token is null or empty"); // 验证输出
                return null;
            }

            Console.WriteLine($"Token retrieved: {token.Length} chars"); // 验证输出
            Console.WriteLine($"Token value: {token}"); // 输出 Token 的具体值

            GitHub.Services.Common.VssCredentials creds = new GitHub.Services.Common.VssCredentials(new VssOAuthAccessTokenCredential(token), CredentialPromptType.DoNotPrompt);
            Console.WriteLine("Credential created"); // 验证输出

            if (creds == null)
            {
                trace.Error("VssCredentials object is null");
                Console.WriteLine("Error: VssCredentials object is null"); // 验证输出
                return null;
            }

            trace.Info($"Credential Type: {creds.Federated.CredentialType}");
            trace.Info($"Prompt Type: {creds.PromptType}");
            Console.WriteLine($"Credential Type: {creds.Federated.CredentialType}"); // 验证输出
            Console.WriteLine($"Prompt Type: {creds.PromptType}"); // 验证输出

            return creds;
        }

        public override void EnsureCredential(IHostContext context, CommandSettings command, string serverUrl)
        {
            ArgUtil.NotNull(context, nameof(context));
            Tracing trace = context.GetTrace(nameof(OAuthAccessTokenCredential));
            trace.Info(nameof(EnsureCredential));
            ArgUtil.NotNull(command, nameof(command));
            CredentialData.Data[Constants.Runner.CommandLine.Args.Token] = command.GetToken();
        }
    }

    public class VssOAuthAccessTokenCredential : FederatedCredential
    {
        public VssOAuthAccessTokenCredential(string accessToken) : this(new VssOAuthAccessToken(accessToken)) { }

        public VssOAuthAccessTokenCredential(JsonWebToken accessToken) : this(new VssOAuthAccessToken(accessToken)) { }

        public VssOAuthAccessTokenCredential(VssOAuthAccessToken accessToken) : base(accessToken) { }

        public override VssCredentialsType CredentialType => VssCredentialsType.OAuth;

        protected override IssuedTokenProvider OnCreateTokenProvider(Uri serverUrl, IHttpResponse response)
        {
            return new VssOAuthAccessTokenProvider(this, serverUrl, null);
        }

        private class VssOAuthAccessTokenProvider : IssuedTokenProvider
        {
            public VssOAuthAccessTokenProvider(IssuedTokenCredential credential, Uri serverUrl, Uri signInUrl)
                : base(credential, serverUrl, signInUrl) { }

            public override bool GetTokenIsInteractive => false;
        }
    }
}
