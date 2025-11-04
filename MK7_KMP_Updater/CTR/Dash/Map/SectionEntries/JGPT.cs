using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class JGPT : KMPSection<JGPTEntry>
    {
        public JGPT(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public JGPT(string magic) : base(magic) { }
    }

    public class JGPTEntry : IKMPSectionEntry
    {
        public Vector3 RespawnPosition { get; }
        public Vector3 RespawnRotation { get; }
        public ushort PointId { get; }
        public ushort Unknown1 { get; }

        public JGPTEntry(EndianReader reader, int fileVersion)
        {
            RespawnPosition = reader.ReadVector3();
            RespawnRotation = reader.ReadVector3();
            PointId = reader.ReadUInt16();
            Unknown1 = reader.ReadUInt16();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteVector3(RespawnPosition);
            writer.WriteVector3(RespawnRotation);
            writer.WriteUInt16(PointId);
            writer.WriteUInt16(Unknown1);
        }
    }
}
