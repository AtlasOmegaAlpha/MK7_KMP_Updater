using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class ConsoleArgument
{
    public string name;
    public string[] aliases;
    public string[] hiddenAliases;
    public string parameter;
    public string description;
    public int nameTabLength;
    public int parameterTabLength;

    public ConsoleArgument(string name, string[] aliases, string[] hiddenAliases, string parameter, string description)
    {
        this.name = name;
        this.aliases = aliases;
        this.hiddenAliases = hiddenAliases;
        this.parameter = parameter;
        this.description = description;

        this.nameTabLength = name.Length + 1;
        foreach (string alias in aliases)
        {
            this.nameTabLength += alias.Length + 4;
        }

        this.parameterTabLength = parameter.Length;
    }
}
