using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class FileUtil
{
    public static void RetrieveFilesWithWildcards(string path, List<string> files, string pathLower = "", List<string>? filesLower = null)
    {
        if (filesLower == null)
            filesLower = new List<string>();

        if (string.IsNullOrWhiteSpace(pathLower))
            pathLower = path.ToLower();

        if (!path.Contains("*") && !path.Contains("?"))
        {
            if (File.Exists(path) && !filesLower.Contains(pathLower))
            {
                files.Add(path);
                filesLower.Add(pathLower);
            }

            return;
        }

        string? directory = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(directory))
            directory = Directory.GetCurrentDirectory();

        bool recursive = path.Contains("**");
        SearchOption searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;

        string pattern = Path.GetFileName(path);
        pattern = pattern.Replace("**\\", "").Replace("**/", "");

        if (string.IsNullOrEmpty(pattern))
            pattern = "*";

        try
        {
            string[] matchedFiles = Directory.GetFiles(directory, pattern, searchOption);
            foreach (string file in matchedFiles)
            {
                string fileL = file.ToLower();
                if (!filesLower.Contains(fileL))
                {
                    files.Add(file);
                    filesLower.Add(fileL);
                }
            }
        }
        catch (Exception ex)
        {
            ConsoleUtil.Error($"Could not process wildcard '{path}': {ex.Message}");
        }
    }
}
