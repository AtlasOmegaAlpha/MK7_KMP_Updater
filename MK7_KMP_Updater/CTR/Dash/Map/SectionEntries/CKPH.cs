using System.Numerics;
using System.Security.AccessControl;

namespace CTR.Dash.Map.SectionEntries
{
    public class CKPH : KMPSection<CKPHEntry>
    {
        public CKPH(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public CKPH(string magic) : base(magic) { }
    }

    public class CKPHEntry : IKMPSectionEntry
    {
        public ushort PointStart { get; }
        public ushort PointCount { get; }
        public ushort[] PreviousGroup { get; }
        public ushort[] NextGroup { get; }
        public ushort Unknown1 { get; }

        public CKPHEntry(EndianReader reader, int fileVersion)
        {
            PointStart = reader.ReadUInt16();
            PointCount = reader.ReadUInt16();
            PreviousGroup = reader.ReadUInt16s(16);
            NextGroup = reader.ReadUInt16s(16);
            Unknown1 = reader.ReadUInt16();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteUInt16(PointStart);
            writer.WriteUInt16(PointCount);
            writer.WriteUInt16s(PreviousGroup);
            writer.WriteUInt16s(NextGroup);
            writer.WriteUInt16(Unknown1);
        }
    }
}
