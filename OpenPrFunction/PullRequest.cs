using System;
using System.Linq;
using System.Threading.Tasks;
using Common;
using Common.TableModels;
using Octokit;
using Octokit.Internal;

namespace OpenPrFunction
{
    public class PullRequest : IPullRequest
    {
        public async Task<Pr> OpenAsync(GitHubClientParameters parameters, bool update, Settings settings = null)
        {
            var inMemoryCredentialStore = new InMemoryCredentialStore(new Credentials(KnownGitHubs.Username, parameters.Password));
            var githubClient = new GitHubClient(new ProductHeaderValue("ImgBot"), inMemoryCredentialStore);

            var repo = await githubClient.Repository.Get(parameters.RepoOwner, parameters.RepoName);
            var branch = await githubClient.Repository.Branch.Get(parameters.RepoOwner, parameters.RepoName, KnownGitHubs.BranchName);
            var commit = await githubClient.Repository.Commit.Get(parameters.RepoOwner, parameters.RepoName, branch.Commit.Sha);

            if (branch == null)
            {
                return null;
            }

            var baseBranch = repo.DefaultBranch;
            if (settings != null && !string.IsNullOrEmpty(settings.DefaultBranchOverride))
            {
                baseBranch = settings.DefaultBranchOverride;
            }

            var stats = Stats.ParseStats(commit.Commit.Message);

            Octokit.PullRequest result;
            if (update)
            {
                // get PR number
                var allPrs = await githubClient.PullRequest.GetAllForRepository(parameters.RepoOwner, parameters.RepoName);

                var pr = allPrs.FirstOrDefault(p => p.State == ItemState.Open && p.Head.Sha == commit.Sha);

                if (pr == null)
                {
                    throw new Exception("Couldn't update PR. PR not found");
                }

                var pru = new PullRequestUpdate()
                {
                    Body = PullRequestBody.Generate(stats),
                };

                result = await githubClient.PullRequest.Update(parameters.RepoOwner, parameters.RepoName, pr.Number, pru);
            }
            else
            {
                var pr = new NewPullRequest(KnownGitHubs.CommitMessageTitle, KnownGitHubs.BranchName, baseBranch)
                {
                    Body = PullRequestBody.Generate(stats),
                };

                result = await githubClient.PullRequest.Create(parameters.RepoOwner, parameters.RepoName, pr);
            }

            if (stats == null)
            {
                return null;
            }

            return new Pr(parameters.RepoOwner)
            {
                RepoName = parameters.RepoName,
                Id = result.Id,
                NumImages = stats.Length == 1 ? 1 : stats.Length - 1,
                Number = result.Number,
                SizeBefore = ImageStat.ToDouble(stats[0].Before),
                SizeAfter = ImageStat.ToDouble(stats[0].After),
                PercentReduced = stats[0].Percent,
            };
        }
    }
}
