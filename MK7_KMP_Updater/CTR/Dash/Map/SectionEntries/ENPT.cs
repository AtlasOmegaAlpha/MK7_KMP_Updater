using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class ENPT : KMPSection<ENPTEntry>
    {
        public ENPT(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public ENPT(string magic) : base(magic) { }
    }

    public class ENPTEntry : IKMPSectionEntry
    {
        public Vector3 PointPosition { get; }
        public float Range { get; }
        public uint Unknown1 { get; }
        public uint Unknown2 { get; }

        public ENPTEntry(EndianReader reader, int fileVersion)
        {
            PointPosition = reader.ReadVector3();
            Range = reader.ReadFloat();
            Unknown1 = reader.ReadUInt32();
            Unknown2 = reader.ReadUInt32();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteVector3(PointPosition);
            writer.WriteFloat(Range);
            writer.WriteUInt32(Unknown1);
            writer.WriteUInt32(Unknown2);
        }
    }
}
