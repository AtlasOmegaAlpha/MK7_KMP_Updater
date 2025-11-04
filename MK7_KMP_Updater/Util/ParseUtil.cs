using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

class ParseUtil
{
    public static int ParseVersionValue(string version)
    {
        int versionInt = -1;
        if (!int.TryParse(version, out versionInt))
            IsHexString(version, out versionInt);

        return versionInt;
    }

    public static bool IsHexString(string value, out int hexValue)
    {
        hexValue = 0;

        if (string.IsNullOrEmpty(value))
            return false;

        string t = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : (value.StartsWith("x", StringComparison.OrdinalIgnoreCase) ? value[1..] : value);

        if (t.All(c => Uri.IsHexDigit(c)))
        {
            hexValue = int.Parse(t, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return true;
        }

        return false;
    }
}
