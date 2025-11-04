using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class GOBJ : KMPSection<GOBJEntry>
    {
        public GOBJ(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public GOBJ(string magic) : base(magic) { }
    }

    public class GOBJEntry : IKMPSectionEntry
    {
        public ushort ObjectId { get; }
        public ushort Unknown1 { get; }
        public Vector3 ObjectPosition { get; }
        public Vector3 ObjectRotation { get; }
        public Vector3 ObjectScale { get; }
        public ushort RouteId { get; }
        public ushort[] ObjectSettings { get; }
        public ushort PresenceFlags { get; }
        public ushort Unknown2 { get; }
        public ushort Unknown3 { get; }

        public GOBJEntry(EndianReader reader, int fileVersion)
        {
            ObjectId = reader.ReadUInt16();
            Unknown1 = reader.ReadUInt16();
            ObjectPosition = reader.ReadVector3();
            ObjectRotation = reader.ReadVector3();
            ObjectScale = reader.ReadVector3();
            RouteId = reader.ReadUInt16();
            ObjectSettings = reader.ReadUInt16s(8);
            PresenceFlags = reader.ReadUInt16();
            Unknown2 = 0xFFFF;
            Unknown3 = 0;
            if (fileVersion > 0xBB8)
            {
                Unknown2 = reader.ReadUInt16();
                Unknown3 = reader.ReadUInt16();
            }
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteUInt16(ObjectId);
            writer.WriteUInt16(Unknown1);
            writer.WriteVector3(ObjectPosition);
            writer.WriteVector3(ObjectRotation);
            writer.WriteVector3(ObjectScale);
            writer.WriteUInt16(RouteId);
            writer.WriteUInt16s(ObjectSettings);
            writer.WriteUInt16(PresenceFlags);
            if (fileVersion > 0xBB8)
            {
                writer.WriteUInt16(Unknown2);
                writer.WriteUInt16(Unknown3);
            }
        }
    }
}
