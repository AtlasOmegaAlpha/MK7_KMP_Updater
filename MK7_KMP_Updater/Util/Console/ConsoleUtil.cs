using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

class ConsoleUtil
{
    public static void Exit()
    {
        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
        Environment.Exit(0);
    }

    public static void Error(string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[Error] {message}");
        Console.ResetColor();
    }

    public static void Warning(string message)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[Warning] {message}");
        Console.ResetColor();
    }

    public static void PrintHelp(string usage, List<ConsoleArgument> arguments)
    {
        Console.WriteLine($"\r\nUsage:\t{usage}\r\n");
        Console.WriteLine("Possible arguments:");

        int nameTabLength = 16;
        int paramTabLength = 9;
        foreach (ConsoleArgument argument in arguments)
        {
            if (argument.nameTabLength > nameTabLength)
                nameTabLength = argument.nameTabLength;

            if (argument.parameterTabLength > paramTabLength)
                paramTabLength = argument.parameterTabLength;
        }

        PrintTableLine(nameTabLength, paramTabLength, TableLineType.Initial, true);

        Console.WriteLine($"{ApplyTabSpacer("Argument (alias)", nameTabLength)} │ {ApplyTabSpacer("Parameter", paramTabLength)} │ Description");

        PrintTableLine(nameTabLength, paramTabLength, TableLineType.Middle, true);

        for (int i = 0; i < arguments.Count; i++)
        {
            PrintArgument(arguments[i], nameTabLength, paramTabLength);
            PrintTableLine(nameTabLength, paramTabLength, i >= arguments.Count - 1 ? TableLineType.Final : TableLineType.Middle, false);
        }
    }

    public static bool RegisterArgument(ref string arg, string[] args, List<ConsoleArgument> arguments, out string originalArg, out bool skipNextArg, out string param)
    {
        skipNextArg = false;
        param = "";
        originalArg = arg;
        if (arg.StartsWith("--"))
            arg = arg.Substring(2);
        else if (arg.StartsWith("-"))
            arg = arg.Substring(1);
        else
            return false;

        string[] argParts = arg.Split([':', '='], 2);
        if (argParts.Length >= 2)
        {
            arg = argParts[0];
            param = argParts[1];
        }

        arg = arg.Replace("-", "").Replace("_", "").Replace(".", "");
        ConsoleArgument? foundArgument = null;
        foreach (ConsoleArgument argument in arguments)
        {
            string argL = arg.ToLower();
            if (argument.name.ToLower().Equals(argL))
            {
                foundArgument = argument;
                break;
            }

            foreach (string alias in argument.aliases)
            {
                if (alias.ToLower().Equals(argL))
                {
                    foundArgument = argument;
                    break;
                }
            }

            if (foundArgument != null)
                break;

            foreach (string alias in argument.hiddenAliases)
            {
                if (alias.ToLower().Equals(argL))
                {
                    foundArgument = argument;
                    break;
                }
            }

            if (foundArgument != null)
                break;
        }

        if (foundArgument == null)
            return false;

        if (string.IsNullOrWhiteSpace(param) && !string.IsNullOrWhiteSpace(foundArgument.parameter))
        {
            int nextArgIdx = Array.IndexOf(args, originalArg) + 1;
            if (nextArgIdx < args.Length)
            {
                param = args[nextArgIdx];
                skipNextArg = true;
            }
        }

        if (!string.IsNullOrWhiteSpace(foundArgument.parameter) && string.IsNullOrWhiteSpace(param))
            return false;

        return true;
    }

    #region Help command: Private methods
    private enum TableLineType
    {
        Initial,
        Middle,
        Final
    }

    private static string ApplyTabSpacer(string s, int maxTabLength)
    {
        while (s.Length < maxTabLength) { s += " "; }
        return s;
    }

    private static void PrintTableLine(int nameTabLength, int paramTabLength, TableLineType type, bool isHeader)
    {
        int currentPos = 0;
        while (currentPos < Console.WindowWidth - 1)
        {
            if (currentPos == nameTabLength + 1 || currentPos == nameTabLength + paramTabLength + 4)
                Console.Write(type switch { TableLineType.Initial => isHeader ? "╤" : "┬", TableLineType.Middle => isHeader ? "╪" : "┼", TableLineType.Final => isHeader ? "╧" : "┴", _ => "─" });
            else
                Console.Write(isHeader ? "═" : "─");
            currentPos++;
        }
        Console.Write(" ");
    }

    private static void PrintArgument(ConsoleArgument argument, int nameTabLength, int paramTabLength)
    {
        StringBuilder sb = new StringBuilder("-" + argument.name);
        foreach (string alias in argument.aliases)
        {
            sb.Append($" (-{alias})");
        }

        string argName = ApplyTabSpacer(sb.ToString(), nameTabLength);
        int currentPos = argName.Length;
        sb = new StringBuilder(argName);
        string argParam = ApplyTabSpacer(argument.parameter, paramTabLength);
        currentPos += argParam.Length + 6;
        sb.Append($" │ {argParam} │ ");
        int startDescPos = currentPos;
        foreach (string word in argument.description.Split(' '))
        {
            if (currentPos + word.Length + 1 > Console.WindowWidth - 1)
            {
                sb.AppendLine();
                currentPos = 0;
                while (currentPos < startDescPos)
                {
                    if (currentPos == nameTabLength + 1 || currentPos == nameTabLength + paramTabLength + 4)
                        sb.Append("│");
                    else
                        sb.Append(" ");
                    currentPos++;
                }
            }

            sb.Append(word + " ");
            currentPos += word.Length + 1;
        }

        Console.WriteLine(sb.ToString());
    }
    #endregion
}
