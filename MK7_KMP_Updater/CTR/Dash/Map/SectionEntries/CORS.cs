using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class CORS : KMPSection<CORSEntry>
    {
        public CORS(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public CORS(string magic) : base(magic) { }
    }

    public class CORSEntry : IKMPSectionEntry
    {
        public uint Unknown1 { get; }
        public Vector3 Position { get; }
        public Vector3 Rotation { get; }
        public Vector3 Scale { get; }
        public ushort Unknown2 { get; }
        public ushort Unknown3 { get; }

        public CORSEntry(EndianReader reader, int fileVersion)
        {
            Unknown1 = reader.ReadUInt32();
            Position = reader.ReadVector3();
            Rotation = reader.ReadVector3();
            Scale = reader.ReadVector3();
            Unknown2 = reader.ReadUInt16();
            Unknown3 = reader.ReadUInt16();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteUInt32(Unknown1);
            writer.WriteVector3(Position);
            writer.WriteVector3(Rotation);
            writer.WriteVector3(Scale);
            writer.WriteUInt16(Unknown2);
            writer.WriteUInt16(Unknown3);
        }
    }
}
