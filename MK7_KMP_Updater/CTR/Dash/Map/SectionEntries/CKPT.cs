using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class CKPT : KMPSection<CKPTEntry>
    {
        public CKPT(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public CKPT(string magic) : base(magic) { }
    }

    public class CKPTEntry : IKMPSectionEntry
    {
        public Vector2 LeftPosition { get; }
        public Vector2 RightPosition { get; }
        public byte JugemPointId { get; }
        public byte PointType { get; }
        public byte PreviousPoint { get; }
        public byte NextPoint { get; }
        public byte Unknown1 { get; }
        public byte Unknown2 { get; }
        public byte Unknown3 { get; }
        public byte Unknown4 { get; }

        public CKPTEntry(EndianReader reader, int fileVersion)
        {
            LeftPosition = reader.ReadVector2();
            RightPosition = reader.ReadVector2();
            JugemPointId = reader.ReadByte();
            PointType = reader.ReadByte();
            PreviousPoint = reader.ReadByte();
            NextPoint = reader.ReadByte();
            Unknown1 = reader.ReadByte();
            Unknown2 = reader.ReadByte();
            Unknown3 = reader.ReadByte();
            Unknown4 = reader.ReadByte();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteVector2(LeftPosition);
            writer.WriteVector2(RightPosition);
            writer.WriteByte(JugemPointId);
            writer.WriteByte(PointType);
            writer.WriteByte(PreviousPoint);
            writer.WriteByte(NextPoint);
            writer.WriteByte(Unknown1);
            writer.WriteByte(Unknown2);
            writer.WriteByte(Unknown3);
            writer.WriteByte(Unknown4);
        }
    }
}
