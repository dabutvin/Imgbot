using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using OpenPrFunction;

namespace Test
{
    [TestClass]
    public class PullRequestBodyTests
    {
        private static string expectedFooter = Environment.NewLine + Environment.NewLine +
                                                "---" +
                                                Environment.NewLine + Environment.NewLine +
                                                "[📝 docs](https://imgbot.net/docs) | " +
                                                "[:octocat: repo](https://github.com/dabutvin/ImgBot) | " +
                                                "[🙋🏾 issues](https://github.com/dabutvin/ImgBot/issues) | " +
                                                "[🏪 marketplace](https://github.com/marketplace/imgbot)" +
                                                Environment.NewLine + Environment.NewLine +
                                                "<i>~Imgbot - Part of [Optimole](https://optimole.com/) family</i>" +
                                                Environment.NewLine;

        [TestMethod]
        public void GivenMultiImageCommitMessage_ShouldFormatMarkdownTable()
        {
            var commitMessage = "[ImgBot] Optimize images" + Environment.NewLine +
                         Environment.NewLine +
                         "*Total -- 854.23kb -> 308.28kb (63.91%)" + Environment.NewLine +
                         Environment.NewLine +
                         "/featurecard.png -- 542.34kb -> 86.13kb (84.12%)" + Environment.NewLine +
                         "/graph.png -- 148.78kb -> 88.71kb (40.38%)" + Environment.NewLine +
                         "/featured-marketplace.png -- 163.11kb -> 133.44kb (18.19%)" + Environment.NewLine +
                         Environment.NewLine +
                         "Signed-off-by: ImgBotApp <ImgBotHelp@gmail.com>" + Environment.NewLine;

            var expectedMarkdown = "## Beep boop. Your images are optimized!" + Environment.NewLine +
                          Environment.NewLine +
                          "Your image file size has been reduced by **64%** 🎉" + Environment.NewLine +
                          Environment.NewLine +
                          "<details>" + Environment.NewLine +
                          "<summary>" + Environment.NewLine +
                          "Details" + Environment.NewLine +
                          "</summary>" + Environment.NewLine +
                          Environment.NewLine +
                          "| File | Before | After | Percent reduction |" + Environment.NewLine +
                          "|:--|:--|:--|:--|" + Environment.NewLine +
                          "| /featurecard.png | 542.34kb | 86.13kb | 84.12% |" + Environment.NewLine +
                          "| /graph.png | 148.78kb | 88.71kb | 40.38% |" + Environment.NewLine +
                          "| /featured-marketplace.png | 163.11kb | 133.44kb | 18.19% |" + Environment.NewLine +
                          "| | | | |" + Environment.NewLine +
                          "| **Total :** | **854.23kb** | **308.28kb** | **63.91%** |" + Environment.NewLine +
                          "</details>" + expectedFooter;

            var result = PullRequestBody.Generate(Stats.ParseStats(commitMessage));

            Assert.AreEqual(expectedMarkdown, result);
        }

        [TestMethod]
        public void GivenZeroPercentReductionCommitMessage_ShouldOmitPercentage()
        {
            var commitMessage = "[ImgBot] Optimize images" + Environment.NewLine +
                         Environment.NewLine +
                         "/featured-marketplace.png -- 163.11kb -> 160.11kb (0.02%)" + Environment.NewLine +
                         Environment.NewLine +
                         "Signed-off-by: ImgBotApp <ImgBotHelp@gmail.com>" + Environment.NewLine;

            var expectedMarkdown = "## Beep boop. Your images are optimized!" + Environment.NewLine +
                          Environment.NewLine +
                          "Your image file size has been reduced!" + Environment.NewLine +
                          Environment.NewLine +
                          "<details>" + Environment.NewLine +
                          "<summary>" + Environment.NewLine +
                          "Details" + Environment.NewLine +
                          "</summary>" + Environment.NewLine +
                          Environment.NewLine +
                          "| File | Before | After | Percent reduction |" + Environment.NewLine +
                          "|:--|:--|:--|:--|" + Environment.NewLine +
                          "| /featured-marketplace.png | 163.11kb | 160.11kb | 0.02% |" + Environment.NewLine +
                          "</details>" + expectedFooter;

            var result = PullRequestBody.Generate(Stats.ParseStats(commitMessage));

            Assert.AreEqual(expectedMarkdown, result);
        }

        [TestMethod]
        public void GivenReductionBelow5PercentCommitMessage_ShouldOmitPercentage()
        {
            var commitMessage = "[ImgBot] Optimize images" + Environment.NewLine +
                         Environment.NewLine +
                         "/featured-marketplace.png -- 163.11kb -> 155.11kb (4.40%)" + Environment.NewLine +
                         Environment.NewLine +
                         "Signed-off-by: ImgBotApp <ImgBotHelp@gmail.com>" + Environment.NewLine;

            var expectedMarkdown = "## Beep boop. Your images are optimized!" + Environment.NewLine +
                          Environment.NewLine +
                          "Your image file size has been reduced!" + Environment.NewLine +
                          Environment.NewLine +
                          "<details>" + Environment.NewLine +
                          "<summary>" + Environment.NewLine +
                          "Details" + Environment.NewLine +
                          "</summary>" + Environment.NewLine +
                          Environment.NewLine +
                          "| File | Before | After | Percent reduction |" + Environment.NewLine +
                          "|:--|:--|:--|:--|" + Environment.NewLine +
                          "| /featured-marketplace.png | 163.11kb | 155.11kb | 4.40% |" + Environment.NewLine +
                          "</details>" + expectedFooter;

            var result = PullRequestBody.Generate(Stats.ParseStats(commitMessage));

            Assert.AreEqual(expectedMarkdown, result);
        }

        [TestMethod]
        public void GivenSingleImageCommitMessage_ShouldFormatMarkdownTable()
        {
            var commitMessage = "[ImgBot] Optimize images" + Environment.NewLine +
                         Environment.NewLine +
                         "/featured-marketplace.png -- 163.11kb -> 133.44kb (18.19%)" + Environment.NewLine +
                         Environment.NewLine +
                         "Signed-off-by: ImgBotApp <ImgBotHelp@gmail.com>" + Environment.NewLine;

            var expectedMarkdown = "## Beep boop. Your images are optimized!" + Environment.NewLine +
                          Environment.NewLine +
                          "Your image file size has been reduced by **18%** 🎉" + Environment.NewLine +
                          Environment.NewLine +
                          "<details>" + Environment.NewLine +
                          "<summary>" + Environment.NewLine +
                          "Details" + Environment.NewLine +
                          "</summary>" + Environment.NewLine +
                          Environment.NewLine +
                          "| File | Before | After | Percent reduction |" + Environment.NewLine +
                          "|:--|:--|:--|:--|" + Environment.NewLine +
                          "| /featured-marketplace.png | 163.11kb | 133.44kb | 18.19% |" + Environment.NewLine +
                          "</details>" + expectedFooter;

            var result = PullRequestBody.Generate(Stats.ParseStats(commitMessage));

            Assert.AreEqual(expectedMarkdown, result);
        }

        [TestMethod]
        public void GivenMultiLineGarbageCommitMessage_ShouldRenderDefaultPrBody()
        {
            var commitMessage = "GARBAGE. something else" + Environment.NewLine + Environment.NewLine +
                               "Some more garbage !!" + Environment.NewLine +
                               "One more garbage" + Environment.NewLine;

            var expectedMarkdown = "Beep boop. Optimizing your images is my life. https://imgbot.net/ for more information."
                + Environment.NewLine + Environment.NewLine;

            var result = PullRequestBody.Generate(Stats.ParseStats(commitMessage));

            Assert.AreEqual(expectedMarkdown, result);
        }

        [TestMethod]
        public void GivenSingleLineGarbageCommitMessage_ShouldRenderDefaultPrBody()
        {
            var commitMessage = "GARBAGE. something else";

            var expectedMarkdown = "Beep boop. Optimizing your images is my life. https://imgbot.net/ for more information."
                + Environment.NewLine + Environment.NewLine;

            var result = PullRequestBody.Generate(Stats.ParseStats(commitMessage));

            Assert.AreEqual(expectedMarkdown, result);
        }

        [TestMethod]
        public void GivenMissingDCOCommitMessage_ShouldFormatMarkdownTable()
        {
            var commitMessage = "[ImgBot] Optimize images" + Environment.NewLine +
                         Environment.NewLine +
                         "*Total -- 854.23kb -> 308.28kb (63.91%)" + Environment.NewLine +
                         Environment.NewLine +
                         "/featurecard.png -- 542.34kb -> 86.13kb (84.12%)" + Environment.NewLine +
                         "/graph.png -- 148.78kb -> 88.71kb (40.38%)" + Environment.NewLine +
                         "/featured-marketplace.png -- 163.11kb -> 133.44kb (18.19%)" + Environment.NewLine;

            var expectedMarkdown = "## Beep boop. Your images are optimized!" + Environment.NewLine +
                          Environment.NewLine +
                          "Your image file size has been reduced by **64%** 🎉" + Environment.NewLine +
                          Environment.NewLine +
                          "<details>" + Environment.NewLine +
                          "<summary>" + Environment.NewLine +
                          "Details" + Environment.NewLine +
                          "</summary>" + Environment.NewLine +
                          Environment.NewLine +
                          "| File | Before | After | Percent reduction |" + Environment.NewLine +
                          "|:--|:--|:--|:--|" + Environment.NewLine +
                          "| /featurecard.png | 542.34kb | 86.13kb | 84.12% |" + Environment.NewLine +
                          "| /graph.png | 148.78kb | 88.71kb | 40.38% |" + Environment.NewLine +
                          "| /featured-marketplace.png | 163.11kb | 133.44kb | 18.19% |" + Environment.NewLine +
                          "| | | | |" + Environment.NewLine +
                          "| **Total :** | **854.23kb** | **308.28kb** | **63.91%** |" + Environment.NewLine +
                          "</details>" + expectedFooter;

            var result = PullRequestBody.Generate(Stats.ParseStats(commitMessage));

            Assert.AreEqual(expectedMarkdown, result);
        }
    }
}
