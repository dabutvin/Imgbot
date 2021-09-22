using System;
using System.Text;

namespace OpenPrFunction
{
    public static class PullRequestBody
    {
        /*
         * Convert the ImageStat[] into a markdown PR body
         */
        public static string Generate(ImageStat[] imageStats)
        {
            if (imageStats == null || imageStats.Length == 0)
            {
                return "Beep boop. Optimizing your images is my life. https://imgbot.net/ for more information."
                    + Environment.NewLine + Environment.NewLine;
            }

            var sb = new StringBuilder();
            sb.AppendLine("## Beep boop. Your images are optimized!");
            sb.AppendLine();

            if (Math.Round(imageStats[0].Percent) < 5)
            {
                sb.AppendLine("Your image file size has been reduced!");
            }
            else
            {
                sb.AppendLine($"Your image file size has been reduced by **{imageStats[0].Percent:N0}%** 🎉");
            }

            sb.AppendLine();
            sb.AppendLine("<details>");

            sb.AppendLine("<summary>");
            sb.AppendLine("Details");
            sb.AppendLine("</summary>");
            sb.AppendLine();

            sb.AppendLine("| File | Before | After | Percent reduction |");
            sb.AppendLine("|:--|:--|:--|:--|");

            if (imageStats.Length == 1)
            {
                sb.AppendLine($"| {imageStats[0].Name} | {imageStats[0].Before} | {imageStats[0].After} | {imageStats[0].Percent:N2}% |");
            }
            else
            {
                // the zeroth item is the total; we print it at the bottom of the table
                for (var i = 1; i < imageStats.Length; i++)
                {
                    sb.AppendLine($"| {imageStats[i].Name} | {imageStats[i].Before} | {imageStats[i].After} | {imageStats[i].Percent:N2}% |");
                }

                sb.AppendLine("| | | | |");
                sb.AppendLine($"| **Total :** | **{imageStats[0].Before}** | **{imageStats[0].After}** | **{imageStats[0].Percent:N2}%** |");
            }

            sb.AppendLine("</details>");
            sb.AppendLine();
            sb.AppendLine("---");
            sb.AppendLine();

            sb.Append("[📝 docs](https://imgbot.net/docs) | ");
            sb.Append("[:octocat: repo](https://github.com/dabutvin/ImgBot) | ");
            sb.Append("[🙋🏾 issues](https://github.com/dabutvin/ImgBot/issues) | ");
            sb.Append("[🏪 marketplace](https://github.com/marketplace/imgbot)");

            sb.AppendLine();
            sb.AppendLine();
            sb.Append("<i>");
            sb.Append("~Imgbot - Part of [Optimole](https://optimole.com/) family");
            sb.Append("</i>");
            sb.AppendLine();
            return sb.ToString();
        }
    }
}
