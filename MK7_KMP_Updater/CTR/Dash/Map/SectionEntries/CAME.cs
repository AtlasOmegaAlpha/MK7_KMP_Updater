using System.Numerics;
using System.Security.AccessControl;

namespace CTR.Dash.Map.SectionEntries
{
    public class CAME : KMPSection<CAMEEntry>
    {
        public CAME(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public CAME(string magic) : base(magic) { }
    }

    public class CAMEEntry : IKMPSectionEntry
    {
        public byte CameraType { get; }
        public byte NextCameraId { get; }
        public byte Unknown1 { get; }
        public byte RouteId { get; }
        public ushort RouteSpeed { get; }
        public ushort FovSpeed { get; }
        public ushort TargetSpeed { get; }
        public byte Unknown2 { get; }
        public byte Unknown3 { get; }
        public Vector3 CameraPosition { get; }
        public Vector3 CameraRotation { get; }
        public float FovStartAngle { get; }
        public float FovEndAngle { get; }
        public Vector3 TargetStartPosition { get; }
        public Vector3 TargetEndPosition { get; }
        public float ActiveTime { get; }

        public CAMEEntry(EndianReader reader, int fileVersion)
        {
            CameraType = reader.ReadByte();
            NextCameraId = reader.ReadByte();
            Unknown1 = reader.ReadByte();
            RouteId = reader.ReadByte();
            RouteSpeed = reader.ReadUInt16();
            FovSpeed = reader.ReadUInt16();
            TargetSpeed = reader.ReadUInt16();
            Unknown2 = reader.ReadByte();
            Unknown3 = reader.ReadByte();
            CameraPosition = reader.ReadVector3();
            CameraRotation = reader.ReadVector3();
            FovStartAngle = reader.ReadFloat();
            FovEndAngle = reader.ReadFloat();
            TargetStartPosition = reader.ReadVector3();
            TargetEndPosition = reader.ReadVector3();
            ActiveTime = reader.ReadFloat();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteByte(CameraType);
            writer.WriteByte(NextCameraId);
            writer.WriteByte(Unknown1);
            writer.WriteByte(RouteId);
            writer.WriteUInt16(RouteSpeed);
            writer.WriteUInt16(FovSpeed);
            writer.WriteUInt16(TargetSpeed);
            writer.WriteByte(Unknown2);
            writer.WriteByte(Unknown3);
            writer.WriteVector3(CameraPosition);
            writer.WriteVector3(CameraRotation);
            writer.WriteFloat(FovStartAngle);
            writer.WriteFloat(FovEndAngle);
            writer.WriteVector3(TargetStartPosition);
            writer.WriteVector3(TargetEndPosition);
            writer.WriteFloat(ActiveTime);
        }
    }
}
