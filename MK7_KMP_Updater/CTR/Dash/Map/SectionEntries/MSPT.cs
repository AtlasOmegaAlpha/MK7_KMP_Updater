using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class MSPT : KMPSection<MSPTEntry>
    {
        public MSPT(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public MSPT(string magic) : base(magic) { }
    }

    public class MSPTEntry : IKMPSectionEntry
    {

        public MSPTEntry(EndianReader reader, int fileVersion)
        {

        }

        public void Write(EndianWriter writer, int fileVersion)
        {

        }
    }
}
