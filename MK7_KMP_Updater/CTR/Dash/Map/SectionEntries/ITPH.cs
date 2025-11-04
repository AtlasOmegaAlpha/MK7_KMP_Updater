using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class ITPH : KMPSection<ITPHEntry>
    {
        public ITPH(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public ITPH(string magic) : base(magic) { }
    }

    public class ITPHEntry : IKMPSectionEntry
    {
        public ushort PointStart { get; }
        public ushort PointCount { get; }
        public ushort[] PreviousGroup { get; }
        public ushort[] NextGroup { get; }

        public ITPHEntry(EndianReader reader, int fileVersion)
        {
            PointStart = reader.ReadUInt16();
            PointCount = reader.ReadUInt16();
            PreviousGroup = reader.ReadUInt16s(16);
            NextGroup = reader.ReadUInt16s(16);
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteUInt16(PointStart);
            writer.WriteUInt16(PointCount);
            writer.WriteUInt16s(PreviousGroup);
            writer.WriteUInt16s(NextGroup);
        }
    }
}
