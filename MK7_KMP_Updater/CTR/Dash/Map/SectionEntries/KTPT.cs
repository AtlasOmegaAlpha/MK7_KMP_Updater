using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class KTPT : KMPSection<KTPTEntry>
    {
        public KTPT(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public KTPT(string magic) : base(magic) { }
    }

    public class KTPTEntry : IKMPSectionEntry
    {
        public Vector3 StartPosition { get; }
        public Vector3 StartRotation { get; }
        public ushort PlayerId { get; }
        public ushort Padding { get; }

        public KTPTEntry(EndianReader reader, int fileVersion)
        {
            StartPosition = reader.ReadVector3();
            StartRotation = reader.ReadVector3();
            PlayerId = reader.ReadUInt16();
            Padding = reader.ReadUInt16();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteVector3(StartPosition);
            writer.WriteVector3(StartRotation);
            writer.WriteUInt16(PlayerId);
            writer.WriteUInt16(Padding);
        }
    }
}
