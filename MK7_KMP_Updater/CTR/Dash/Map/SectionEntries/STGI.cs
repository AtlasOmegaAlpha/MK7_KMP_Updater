using System.Numerics;

namespace CTR.Dash.Map.SectionEntries
{
    public class STGI : KMPSection<STGIEntry>
    {
        public STGI(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion) { }
        public STGI(string magic) : base(magic) { }
    }

    public class STGIEntry : IKMPSectionEntry
    {
        public byte Unknown1;
        public byte Unknown2;
        public byte Unknown3;
        public byte Unknown4;
        public uint Unknown5;
        public ushort Unknown6;
        public ushort Unknown7;

        public STGIEntry(EndianReader reader, int fileVersion)
        {
            Unknown1 = reader.ReadByte();
            Unknown2 = reader.ReadByte();
            Unknown3 = reader.ReadByte();
            Unknown4 = reader.ReadByte();
            Unknown5 = reader.ReadUInt32();
            Unknown6 = reader.ReadUInt16();
            Unknown7 = reader.ReadUInt16();
        }

        public void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteByte(Unknown1);
            writer.WriteByte(Unknown2);
            writer.WriteByte(Unknown3);
            writer.WriteByte(Unknown4);
            writer.WriteUInt32(Unknown5);
            writer.WriteUInt16(Unknown6);
            writer.WriteUInt16(Unknown7);
        }
    }
}
