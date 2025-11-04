using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class AREA : KMPSection<AREAEntry>
    {
        public AREA(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public AREA(string magic) : base(magic) { }
    }

    public class AREAEntry : IKMPSectionEntry
    {
        public byte ShapeType { get; }
        public byte AreaType { get; }
        public byte CameraId { get; }
        public byte Priority { get; }
        public Vector3 AreaPosition { get; }
        public Vector3 AreaRotation { get; }
        public Vector3 AreaScale { get; }
        public ushort Unknown1 { get; }
        public ushort Unknown2 { get; }
        public ushort Unknown3 { get; }
        public ushort Unknown4 { get; }

        public AREAEntry(EndianReader reader, int fileVersion)
        {
            ShapeType = reader.ReadByte();
            AreaType = reader.ReadByte();
            CameraId = reader.ReadByte();
            Priority = reader.ReadByte();
            AreaPosition = reader.ReadVector3();
            AreaRotation = reader.ReadVector3();
            AreaScale = reader.ReadVector3();
            Unknown1 = reader.ReadUInt16();
            Unknown2 = reader.ReadUInt16();
            Unknown3 = reader.ReadUInt16();
            Unknown4 = reader.ReadUInt16();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteByte(ShapeType);
            writer.WriteByte(AreaType);
            writer.WriteByte(CameraId);
            writer.WriteByte(Priority);
            writer.WriteVector3(AreaPosition);
            writer.WriteVector3(AreaRotation);
            writer.WriteVector3(AreaScale);
            writer.WriteUInt16(Unknown1);
            writer.WriteUInt16(Unknown2);
            writer.WriteUInt16(Unknown3);
            writer.WriteUInt16(Unknown4);
        }
    }
}
