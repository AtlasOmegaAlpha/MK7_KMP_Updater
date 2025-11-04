namespace CTR.Dash.Map
{
    public interface IKMPSection
    {
        string SectionMagic { get; }
        ushort EntryCount { get; }
        ushort ExtraValue { get; }
        List<IKMPSectionEntry> Entries { get; }

        void Write(EndianWriter writer, int fileVersion);
    }

    public interface IKMPSectionEntry
    {
        void Write(EndianWriter writer, int fileVersion);
    }

    public abstract class KMPSection : IKMPSection
    {
        public string SectionMagic { get; protected set; }
        public ushort EntryCount { get; protected set; }
        public ushort ExtraValue { get; protected set; }
        public List<IKMPSectionEntry> Entries { get; protected set; } = new();

        protected KMPSection(EndianReader reader, string magic, int fileVersion)
        {
            SectionMagic = magic;
            EntryCount = reader.ReadUInt16();
            ExtraValue = reader.ReadUInt16();
        }

        protected KMPSection(string magic)
        {
            SectionMagic = magic;
            EntryCount = 0;
            ExtraValue = 0;
        }

        protected abstract IKMPSectionEntry ReadEntry(EndianReader reader, int fileVersion);

        public virtual void Write(EndianWriter writer, int fileVersion)
        {
            writer.WriteString(SectionMagic);
            writer.WriteUInt16((ushort)Entries.Count);
            writer.WriteUInt16(ExtraValue);

            foreach (IKMPSectionEntry entry in Entries)
            {
                entry.Write(writer, fileVersion);
            }
        }
    }

    public class KMPSection<TEntry> : KMPSection where TEntry : IKMPSectionEntry
    {
        public new List<TEntry> Entries { get; private set; } = new();

        public KMPSection(EndianReader reader, string magic, int fileVersion) : base(reader, magic, fileVersion)
        {
            for (int i = 0; i < EntryCount; i++)
            {
                TEntry entry = (TEntry)Activator.CreateInstance(typeof(TEntry), reader, fileVersion)!;
                Entries.Add(entry);
                base.Entries.Add(entry);
            }
        }

        public KMPSection(string magic) : base(magic) { }

        protected override IKMPSectionEntry ReadEntry(EndianReader reader, int fileVersion) => throw new NotImplementedException();

        public override void Write(EndianWriter writer, int fileVersion)
        {
            EntryCount = (ushort)Entries.Count;
            base.Write(writer, fileVersion);
        }
    }
}
