using System.IO;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace amsdec
{
    class Program
    {
        static void Main(string[] args)
        {
            foreach (string arg in args)
            {
                ReadFile(arg);
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        static void ReadFile(string file)
        {
            if (!File.Exists(file))
                return;

            EndianReader reader = new EndianReader(File.ReadAllBytes(file), Endianness.LittleEndian);
            string magic = reader.ReadString(4);
            if (magic != "DMDC")
            {
                Console.WriteLine("Invalid magic: " + magic);
                return;
            }

            uint fileSize = reader.ReadUInt32();
            ushort nrSections = reader.ReadUInt16();
            ushort headerSize = reader.ReadUInt16();
            int fileVersion = reader.ReadInt32();
            int sectionStartOffset = nrSections * 4 + 0x10;

            if (nrSections <= 0)
            {
                Console.WriteLine("Invalid nrSections: " + nrSections);
                return;
            }

            Dictionary<string, KMPSection> sections = new Dictionary<string, KMPSection>();
            for (int i = 0; i < nrSections; i++)
            {
                KMPSection section = ReadSection(reader, fileVersion, sectionStartOffset);
                if (section == null)
                    continue;

                if (sections.ContainsKey(section.sectionMagic))
                {
                    Console.WriteLine("Duplicate section: " + section.sectionMagic);
                    continue;
                }

                sections.Add(section.sectionMagic, section);
            }

            reader.Close();

            string newPath = Path.ChangeExtension(file, ".new.kmp");
            EndianWriter writer = new EndianWriter(File.Open(newPath, FileMode.Create), Endianness.LittleEndian);
            writer.WriteString("DMDC");
            writer.Position += 4;
            writer.WriteUInt16(0x12);
            writer.WriteUInt16(0x58);
            writer.WriteInt32(0xC1C);

            List<KeyValuePair<string, KMPSection>> orderedSections = new List<KeyValuePair<string, KMPSection>>();
            AddSection(orderedSections, sections, "TPTK");
            AddSection(orderedSections, sections, "TPNE");
            AddSection(orderedSections, sections, "HPNE");
            AddSection(orderedSections, sections, "TPTI");
            AddSection(orderedSections, sections, "HPTI");
            AddSection(orderedSections, sections, "TPKC");
            AddSection(orderedSections, sections, "HPKC");
            AddSection(orderedSections, sections, "JBOG");
            AddSection(orderedSections, sections, "ITOP");
            AddSection(orderedSections, sections, "AERA");
            AddSection(orderedSections, sections, "EMAC");
            AddSection(orderedSections, sections, "TPGJ");
            AddSection(orderedSections, sections, "TPNC");
            AddSection(orderedSections, sections, "TPSM");
            AddSection(orderedSections, sections, "IGTS");
            AddSection(orderedSections, sections, "SROC");
            AddSection(orderedSections, sections, "TPLG");
            AddSection(orderedSections, sections, "HPLG");

            uint currentSectionPos = 0x12 * 4 + 0x10;
            writer.Position += 4;
            foreach (KeyValuePair<string, KMPSection> section in orderedSections)
            {
                long currentPos = writer.Position;
                writer.Position = currentSectionPos;
                writer.WriteString(section.Value.sectionMagic);
                writer.WriteUInt16(section.Value.nrEntries);
                writer.WriteUInt16(section.Value.extraValue);
                for (int j = 0; j < section.Value.nrEntries; j++)
                {
                    if (section.Value.entryData[j] != null && section.Value.entryData[j].Length > 0)
                        writer.WriteBytes(section.Value.entryData[j]);
                }

                if (section.Key == "HPLG")
                    break;

                uint nextSectionPos = (uint)writer.Position;
                writer.Position = currentPos;
                writer.WriteUInt32(nextSectionPos - (0x12 * 4 + 0x10));
                currentSectionPos = nextSectionPos;
            }

            writer.Position = 0x4;
            writer.WriteUInt32((uint)writer.StreamLength);
            writer.Close();
            Console.WriteLine("Converted file: " + newPath);
        }

        static KMPSection ReadSection(EndianReader reader, int fileVersion, int sectionStartOffset)
        {
            uint sectionOffset = reader.ReadUInt32();
            long currentPos = reader.Position;
            reader.Position = sectionOffset + sectionStartOffset;
            KMPSection section = new KMPSection(reader, fileVersion);
            reader.Position = currentPos;
            return section;
        }

        static void AddSection(List<KeyValuePair<string, KMPSection>> orderedSections, Dictionary<string, KMPSection> sections, string magic)
        {
            if (sections.ContainsKey(magic))
                orderedSections.Add(new KeyValuePair<string, KMPSection>(magic, sections[magic]));
            else
                orderedSections.Add(new KeyValuePair<string, KMPSection>(magic, new KMPSection(magic)));
        }
    }

    class KMPSection
    {
        public string sectionMagic;
        public ushort nrEntries;
        public ushort extraValue;
        public List<byte[]> entryData;

        public KMPSection(string magic)
        {
            this.sectionMagic = magic;
            this.nrEntries = 0;
            this.extraValue = 0;
            this.entryData = new List<byte[]>();
        }

        public KMPSection(EndianReader reader, int fileVersion)
        {
            this.sectionMagic = reader.ReadString(4);
            this.nrEntries = reader.ReadUInt16();
            this.extraValue = reader.ReadUInt16();
            this.entryData = new List<byte[]>();
            for (int i = 0; i < this.nrEntries; i++)
            {
                switch (this.sectionMagic)
                {
                    case "TPTK":
                        this.entryData.Add(reader.ReadBytes(0x1C));
                        break;

                    case "TPNE":
                        this.entryData.Add(reader.ReadBytes(0x18));
                        break;

                    case "HPNE":
                        this.entryData.Add(reader.ReadBytes(0x48));
                        break;

                    case "TPTI":
                        this.entryData.Add(reader.ReadBytes(0x14));
                        break;

                    case "HPTI":
                        this.entryData.Add(reader.ReadBytes(0x1C));
                        break;

                    case "TPKC":
                        this.entryData.Add(reader.ReadBytes(0x18));
                        break;

                    case "HPKC":
                        this.entryData.Add(reader.ReadBytes(0x10));
                        break;

                    case "JBOG":
                        byte[] bytes = reader.ReadBytes(fileVersion <= 0xBB8 ? 0x3C : 0x40);
                        if (fileVersion <= 0xBB8)
                        {
                            byte[] extraBytes = new byte[] { 0xFF, 0xFF, 0x00, 0x00 };
                            byte[] newBytes = new byte[bytes.Length + extraBytes.Length];
                            Buffer.BlockCopy(bytes, 0, newBytes, 0, bytes.Length);
                            Buffer.BlockCopy(extraBytes, 0, newBytes, bytes.Length, extraBytes.Length);
                            this.entryData.Add(newBytes);
                        }
                        else
                            this.entryData.Add(bytes);
                        break;

                    case "ITOP":
                        ushort nrPoints = reader.ReadUInt16();
                        reader.Position -= 2;
                        this.entryData.Add(reader.ReadBytes(4 + nrPoints * 0x10));
                        break;

                    case "AERA":
                        this.entryData.Add(reader.ReadBytes(0x30));
                        break;

                    case "EMAC":
                        this.entryData.Add(reader.ReadBytes(0x48));
                        break;

                    case "TPGJ":
                        this.entryData.Add(reader.ReadBytes(0x1C));
                        break;

                    case "TPNC":
                        break;

                    case "TPSM":
                        break;

                    case "IGTS":
                        this.entryData.Add(reader.ReadBytes(0x0C));
                        break;

                    case "SROC":
                        break;

                    case "TPLG":
                        this.entryData.Add(reader.ReadBytes(0x18));
                        break;

                    case "HPLG":
                        this.entryData.Add(reader.ReadBytes(0x0C));
                        break;

                    default:
                        Console.WriteLine("Unknown section magic: " + this.sectionMagic);
                        break;
                }
            }
        }
    }
}
