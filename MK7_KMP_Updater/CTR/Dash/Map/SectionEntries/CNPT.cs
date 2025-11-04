using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class CNPT : KMPSection<CNPTEntry>
    {
        public CNPT(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public CNPT(string magic) : base(magic) { }
    }

    public class CNPTEntry : IKMPSectionEntry
    {

        public CNPTEntry(EndianReader reader, int fileVersion)
        {
            
        }

        public void Write(EndianWriter writer, int fileVersion)
        {

        }
    }
}
