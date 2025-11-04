using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class ITPT : KMPSection<ITPTEntry>
    {
        public ITPT(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public ITPT(string magic) : base(magic) { }
    }

    public class ITPTEntry : IKMPSectionEntry
    {
        public Vector3 PointPosition { get; }
        public float Range { get; }
        public uint Unknown1 { get; }

        public ITPTEntry(EndianReader reader, int fileVersion)
        {
            PointPosition = reader.ReadVector3();
            Range = reader.ReadFloat();
            Unknown1 = reader.ReadUInt32();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteVector3(PointPosition);
            writer.WriteFloat(Range);
            writer.WriteUInt32(Unknown1);
        }
    }
}
