using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class GLPT : KMPSection<GLPTEntry>
    {
        public GLPT(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public GLPT(string magic) : base(magic) { }
    }

    public class GLPTEntry : IKMPSectionEntry
    {
        public Vector3 Position { get; }
        public float Range { get; }
        public uint Unknown1 { get; }
        public uint Unknown2 { get; }

        public GLPTEntry(EndianReader reader, int fileVersion)
        {
            Position = reader.ReadVector3();
            Range = reader.ReadFloat();
            Unknown1 = reader.ReadUInt32();
            Unknown2 = reader.ReadUInt32();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteVector3(Position);
            writer.WriteFloat(Range);
            writer.WriteUInt32(Unknown1);
            writer.WriteUInt32(Unknown2);
        }
    }
}
