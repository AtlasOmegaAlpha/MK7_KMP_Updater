using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class POTI : KMPSection<POTIEntry>
    {
        public POTI(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public POTI(string magic) : base(magic) { }
    }

    public class POTIEntry : IKMPSectionEntry
    {
        public ushort PointCount { get; }
        public byte Setting1 { get; }
        public byte Setting2 { get; }
        public List<POTIPoint> Points { get; }

        public POTIEntry(EndianReader reader, int fileVersion)
        {
            PointCount = reader.ReadUInt16();
            Setting1 = reader.ReadByte();
            Setting2 = reader.ReadByte();
            Points = new List<POTIPoint>();
            for (int i = 0; i < PointCount; i++)
            {
                POTIPoint point = new POTIPoint(reader);
                Points.Add(point);
            }
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteUInt16(PointCount);
            writer.WriteByte(Setting1);
            writer.WriteByte(Setting2);
            foreach (POTIPoint point in Points)
            {
                point.Write(writer, fileVersion);
            }
        }
    }

    public class POTIPoint
    {
        public Vector3 Position { get; }
        public ushort Setting1 { get; }
        public ushort Setting2 { get; }

        public POTIPoint(EndianReader reader)
        {
            Position = reader.ReadVector3();
            Setting1 = reader.ReadUInt16();
            Setting2 = reader.ReadUInt16();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteVector3(Position);
            writer.WriteUInt16(Setting1);
            writer.WriteUInt16(Setting2);
        }
    }
}
