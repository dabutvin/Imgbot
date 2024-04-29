using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.WindowsAzure.Storage.Table;
using Newtonsoft.Json;

namespace Auth
{
    public static class AuthFunction
    {
        private static readonly HttpClient HttpClient = new HttpClient();
        private static readonly string WebHost = "https://imgbot.net";
        private static readonly string GithubAuthorizeUrl = "https://github.com/login/oauth/authorize";
        private static readonly string GithubAccessTokenUrl = "https://github.com/login/oauth/access_token";
        private static readonly string GithubUserUrl = "https://api.github.com/user";
        private static readonly string GithubMarketplaceUrl = "https://api.github.com/user/marketplace_purchases";
        private static readonly string GithubEducationUrl = "https://education.github.com/api/user";

        [FunctionName("SetupFunction")]
        public static HttpResponseMessage Setup(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "setup")] HttpRequestMessage req,
            ExecutionContext executionContext)
        {
            var secrets = Secrets.Get(executionContext);
            var state = Guid.NewGuid().ToString();
            var from = req.RequestUri.ParseQueryString().Get("from");
            if (from == "app")
            {
                state += ",fromapp";
            }

            var authorizeUrl = $"{GithubAuthorizeUrl}?client_id={secrets.ClientId}&redirect_uri={secrets.RedirectUri}&state={state}";
            return req.CreateResponse().SetCookie("state", state).SetRedirect(authorizeUrl);
        }

        [FunctionName("CallbackFunction")]
        public static async Task<HttpResponseMessage> Callback(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "callback")] HttpRequestMessage req,
            ExecutionContext executionContext,
            ILogger logger)
        {
            try
            {
                var secrets = Secrets.Get(executionContext);
                var storageAccount = CloudStorageAccount.Parse(Common.KnownEnvironmentVariables.AzureWebJobsStorage);
                var marketplaceTable = storageAccount.CreateCloudTableClient().GetTableReference("marketplace");

                var stateCookie = req.ReadCookie("state");
                if (string.IsNullOrEmpty(stateCookie))
                {
                    logger.LogError("State cookie is missing");
                    return Winning(req);
                }

                var qs = req.RequestUri.ParseQueryString();
                var stateQuery = qs.Get("state");
                var code = qs.Get("code");

                if (stateQuery != stateCookie)
                {
                    logger.LogError("State mismatch: {StateCookie} !== {StateQuery}", stateCookie, stateQuery);
                    return Winning(req);
                }

                if (string.IsNullOrEmpty(code))
                {
                    logger.LogError("Code is missing");
                    return Winning(req);
                }

                var tokenResponse = await HttpClient.PostAsync(GithubAccessTokenUrl, new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("client_id", secrets.ClientId),
                    new KeyValuePair<string, string>("client_secret", secrets.ClientSecret),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", secrets.RedirectUri),
                    new KeyValuePair<string, string>("state", stateQuery)
                }));

                var tokenContent = await tokenResponse.Content.ReadAsFormDataAsync();
                if (tokenContent.Get("error") != null)
                {
                    logger.LogError("TokenResponse: " + await tokenResponse.Content.ReadAsStringAsync());
                    return Winning(req);
                }

                var token = tokenContent.Get("access_token");

                var mktplcResponse = await HttpClient.GetAsync($"{GithubMarketplaceUrl}?access_token={token}");
                var planDataJson = await mktplcResponse.Content.ReadAsStringAsync();
                var planData = JsonConvert.DeserializeObject<PlanData[]>(planDataJson);

                var eduResponse = await HttpClient.GetAsync($"{GithubEducationUrl}?access_token={token}");
                var eduDataJson = await eduResponse.Content.ReadAsStringAsync();
                var eduData = JsonConvert.DeserializeObject<Edu>(eduDataJson);
                var isStudent = eduData?.Student ?? false;

                foreach (var item in planData)
                {
                    var marketplaceRow = new Marketplace(item.account.id, item.account.login)
                    {
                        AccountType = item.account.type,
                        PlanId = item.plan.id,
                        Student = isStudent,
                    };
                    await marketplaceTable.CreateIfNotExistsAsync();
                    await marketplaceTable.ExecuteAsync(TableOperation.InsertOrMerge(marketplaceRow));
                }

                if (planData.Length == 0 && isStudent)
                {
                    var userResponse = await HttpClient.GetAsync($"{GithubUserUrl}?access_token={token}");
                    var userDataJson = await userResponse.Content.ReadAsStringAsync();
                    var userData = JsonConvert.DeserializeObject<Account>(userDataJson);
                    var marketplaceRow = new Marketplace(userData.id, userData.login)
                    {
                        AccountType = userData.type,
                        PlanId = 1337,
                        Student = isStudent,
                    };

                    await marketplaceTable.CreateIfNotExistsAsync();
                    await marketplaceTable.ExecuteAsync(TableOperation.InsertOrMerge(marketplaceRow));
                }

                return Winning(req, token, stateQuery);
            }
            catch (Exception e)
            {
                logger.LogError(e, "Error processing auth");
            }

            return Winning(req);
        }

        private static HttpResponseMessage Winning(HttpRequestMessage req, string token = null, string state = null)
        {
            var response = req.CreateResponse();
            if (token != null)
            {
                response.SetCookie("token", token);
            }

            var redirectUrl = state?.Contains(",fromapp") == true ? $"{WebHost}/app" : $"{WebHost}/winning";
            response.SetRedirect(redirectUrl);

            return response;
        }

        [FunctionName("IsAuthenticatedFunction")]
        public static HttpResponseMessage IsAuthenticated(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "isauthenticated")] HttpRequestMessage req)
        {
            var tokenCookie = req.ReadCookie("token");
            var isAuthenticated = !string.IsNullOrEmpty(tokenCookie);
            return req.CreateResponse().SetJson(new { result = isAuthenticated }).EnableCors();
        }

        [FunctionName("SignoutFunction")]
        public static HttpResponseMessage Signout(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "signout")] HttpRequestMessage req)
        {
            return req.CreateResponse()
                .SetCookie("token", "rubbish", new DateTime(1970, 1, 1))
                .SetRedirect($"{WebHost}/app");
        }
    }
}
