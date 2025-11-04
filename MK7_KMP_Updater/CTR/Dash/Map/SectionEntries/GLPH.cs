using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class GLPH : KMPSection<GLPHEntry>
    {
        public GLPH(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public GLPH(string magic) : base(magic) { }
    }

    public class GLPHEntry : IKMPSectionEntry
    {
        public byte PointStart { get; }
        public byte PointCount { get; }
        public byte[] PreviousGroup { get; }
        public byte[] NextGroup { get; }
        public uint Unknown1 { get; }
        public uint Unknown2 { get; }

        public GLPHEntry(EndianReader reader, int fileVersion)
        {
            PointStart = reader.ReadByte();
            PointCount = reader.ReadByte();
            PreviousGroup = reader.ReadBytes(6);
            NextGroup = reader.ReadBytes(6);
            Unknown1 = reader.ReadUInt32();
            Unknown2 = reader.ReadUInt32();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteByte(PointStart);
            writer.WriteByte(PointCount);
            writer.WriteBytes(PreviousGroup);
            writer.WriteBytes(NextGroup);
            writer.WriteUInt32(Unknown1);
            writer.WriteUInt32(Unknown2);
        }
    }
}
