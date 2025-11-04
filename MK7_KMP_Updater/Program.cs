using CTR.Dash;
using CTR.Dash.Map;
using System;
using System.Globalization;
using System.IO;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace amsdec
{
    class Program
    {
        const int KMP_DEFAULT_VERSION = 0xC1C;
        static List<ConsoleArgument> arguments =
            [
                new ConsoleArgument("help", ["h"], [], "", "Displays this tool's usage and list of possible arguments"),
                new ConsoleArgument("version", ["v"], [], "Version", $"Converts the KMP to the specified version. Currently supported versions: 0x{KMP_DEFAULT_VERSION.ToString("X")}, 0xBB8"),
                new ConsoleArgument("excludesection", ["e"], ["es", "excludesections"], "Sections", "Completely excludes the specified comma-separated sections from the file"),
                new ConsoleArgument("excludeentry", ["ee"], ["excludeentries"], "Sections", "Excludes any entries from the specified comma-separated sections from the file, leaving these sections empty")
            ];

        static void Main(string[] args)
        {
            List<string> files = new List<string>();
            List<string> filesLower = new List<string>();
            List<string> excludeSections = new List<string>();
            List<string> excludeEntries = new List<string>();
            int version = -1;
            bool skipNextArg = false;
            foreach (string arg in args)
            {
                if (skipNextArg)
                {
                    skipNextArg = false;
                    continue;
                }

                string argL = arg.ToLower();

                if (HandleArgs(argL, args, ref version, ref excludeSections, ref excludeEntries, out skipNextArg))
                    continue;

                FileUtil.RetrieveFilesWithWildcards(arg, files, argL, filesLower);
            }

            if (files.Count <= 0)
            {
                Console.WriteLine("Error: No valid file(s) found");
                PrintHelp();
                return;
            }
            
            if (version == -1)
                version = KMP_DEFAULT_VERSION;

            switch (version)
            {
                case KMP_DEFAULT_VERSION:
                case 0xBB8:
                    break;

                default:
                    Console.WriteLine("Unsupported version: 0x" + version.ToString("X"));
                    ConsoleUtil.Exit();
                    break;
            }

            Console.WriteLine("Converting to version: 0x" + version.ToString("X"));

            foreach (string file in files)
            {
                ReadFile(file, version, excludeSections, excludeEntries);
            }

            ConsoleUtil.Exit();
        }

        public static void PrintHelp()
        {
            ConsoleUtil.PrintHelp("MK7_KMP_Updater [file1, file2 ...]", arguments);
        }

        static bool HandleArgs(string arg, string[] args, ref int version, ref List<string> excludeSections, ref List<string> excludeEntries, out bool skipNextArg)
        {
            if (!ConsoleUtil.RegisterArgument(ref arg, args, arguments, out string originalArg, out skipNextArg, out string param))
                return false;

            if (version == -1 && (arg == "v" || arg == "version"))
            {
                int intVersion = ParseUtil.ParseVersionValue(param);
                if (intVersion != -1)
                    version = intVersion;
                return true;
            }

            switch (arg)
            {
                case "h":
                case "help":
                    PrintHelp();
                    break;

                case "e":
                case "es":
                case "excludesection":
                case "excludesections":
                    {
                        string[] sections = param.Split(',', StringSplitOptions.RemoveEmptyEntries);
                        foreach (string section in sections)
                        {
                            string sectionU = section.ToUpper();
                            if (!excludeSections.Contains(sectionU))
                                excludeSections.Add(sectionU);
                        }
                    }
                    break;

                case "ee":
                case "excludeentry":
                case "excludeentries":
                    {
                        string[] sections = param.Split(',', StringSplitOptions.RemoveEmptyEntries);
                        foreach (string section in sections)
                        {
                            string sectionU = section.ToUpper();
                            if (!excludeEntries.Contains(sectionU))
                                excludeEntries.Add(sectionU);
                        }
                    }
                    break;

                default:
                    return false;
            }

            return true;
        }

        static void ReadFile(string file, int version, List<string> excludeSections, List<string> excludeEntries)
        {
            KMP kmp = new KMP();
            EndianReader reader = new EndianReader(File.OpenRead(file), Endianness.LittleEndian);
            if (!kmp.Read(reader))
            {
                reader.Close();
                ConsoleUtil.Error($"Invalid file: {file}");
                return;
            }

            string newPath = Path.ChangeExtension(file, ".converted.kmp");
            EndianWriter writer = new EndianWriter(File.Open(newPath, FileMode.Create), Endianness.LittleEndian);
            if (!kmp.Write(writer, version, excludeSections, excludeEntries))
            {
                writer.Close();
                ConsoleUtil.Error($"Could not write file: {newPath}");
                return;
            }
            
            Console.WriteLine("Converted file: " + newPath);
        }
    }
}
