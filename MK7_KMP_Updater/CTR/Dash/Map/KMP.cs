using CTR.Dash;
using CTR.Dash.Map.SectionEntries;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CTR.Dash.Map
{
    public class KMP
    {
        const string KMP_MAGIC = "DMDC";
        Dictionary<string, IKMPSection> Sections { get; }

        public KMP()
        {
            Sections = new Dictionary<string, IKMPSection>();
        }

        public bool Read(EndianReader reader)
        {
            if (reader.StreamLength < 0x10)
            {
                ConsoleUtil.Error($"Invalid file size: {reader.StreamLength}");
                return false;
            }

            string magic = reader.ReadString(4);
            if (magic != KMP_MAGIC)
            {
                ConsoleUtil.Error($"Invalid magic: {magic}");
                return false;
            }

            uint fileSize = reader.ReadUInt32();
            ushort nrSections = reader.ReadUInt16();
            ushort headerSize = reader.ReadUInt16();
            int fileVersion = reader.ReadInt32();
            int sectionStartOffset = nrSections * 4 + 0x10;

            for (int i = 0; i < nrSections; i++)
            {
                IKMPSection? section = ReadSection(reader, fileVersion, sectionStartOffset);
                if (section == null)
                    continue;

                if (Sections.ContainsKey(section.SectionMagic))
                {
                    ConsoleUtil.Warning($"Duplicate section: {section.SectionMagic}; skipping");
                    continue;
                }

                Sections.Add(section.SectionMagic, section);
            }

            reader.Close();
            return true;
        }

        public bool Write(EndianWriter writer, int fileVersion, List<string> excludeSections, List<string> excludeEntries)
        {
            List<KeyValuePair<string, IKMPSection>> orderedSections = new List<KeyValuePair<string, IKMPSection>>();

            ushort nrSections = 0;
            void AddSection(string magic)
            {
                if (excludeSections.Contains(magic) || excludeSections.Contains(new string(magic.Reverse().ToArray())))
                    return;

                if (Sections.ContainsKey(magic) && !excludeEntries.Contains(magic) && !excludeEntries.Contains(new string(magic.Reverse().ToArray())))
                    orderedSections.Add(new KeyValuePair<string, IKMPSection>(magic, Sections[magic]));
                else
                {
                    IKMPSection? section = CreateSection(magic);
                    if (section == null)
                    {
                        ConsoleUtil.Error($"Couldn't create section with magic {magic}");
                        ConsoleUtil.Exit();
                        return;
                    }

                    orderedSections.Add(new KeyValuePair<string, IKMPSection>(magic, section));
                }

                nrSections++;
            }

            AddSection("TPTK");
            AddSection("TPNE");
            AddSection("HPNE");
            AddSection("TPTI");
            AddSection("HPTI");
            AddSection("TPKC");
            AddSection("HPKC");
            AddSection("JBOG");
            AddSection("ITOP");
            AddSection("AERA");
            AddSection("EMAC");
            AddSection("TPGJ");
            AddSection("TPNC");
            AddSection("TPSM");
            AddSection("IGTS");
            AddSection("SROC");
            if (fileVersion > 0xBB8)
            {
                AddSection("TPLG");
                AddSection("HPLG");
            }

            writer.WriteString(KMP_MAGIC);
            writer.Position += 4;
            writer.WriteUInt16(nrSections);
            ushort firstSectionPos = (ushort)(nrSections * 4 + 0x10);
            writer.WriteUInt16(firstSectionPos);
            writer.WriteInt32(fileVersion);
            writer.Position += 4;

            uint currentSectionPos = firstSectionPos;
            int i = 0;
            foreach (KeyValuePair<string, IKMPSection> section in orderedSections)
            {
                long currentPos = writer.Position;
                writer.Position = currentSectionPos;
                section.Value.Write(writer, fileVersion);
                if (i >= orderedSections.Count - 1)
                    break;

                currentSectionPos = (uint)writer.Position;
                writer.Position = currentPos;
                writer.WriteUInt32(currentSectionPos - firstSectionPos);
                i++;
            }

            writer.Position = 0x4;
            writer.WriteUInt32((uint)writer.StreamLength);
            writer.Close();
            return true;
        }

        static IKMPSection? ReadSection(EndianReader reader, int fileVersion, int sectionStartOffset)
        {
            uint sectionOffset = reader.ReadUInt32();
            long currentPos = reader.Position;
            reader.Position = sectionOffset + sectionStartOffset;
            IKMPSection? section = CreateSection(reader, fileVersion);
            reader.Position = currentPos;
            return section;
        }

        public static IKMPSection? CreateSection(EndianReader reader, int fileVersion)
        {
            string magic = reader.ReadString(4);
            string className = new string(magic.Reverse().ToArray());
            string fullType = $"CTR.Dash.Map.SectionEntries.{className}";
            Type? sectionType = Type.GetType(fullType);
            if (sectionType == null)
            {
                ConsoleUtil.Warning($"Unknown section magic: {magic}; skipping");
                return null;
            }

            object? instance = Activator.CreateInstance(sectionType, reader, magic, fileVersion);
            if (instance is not IKMPSection section)
            {
                ConsoleUtil.Warning($"Unknown section magic: {magic}; skipping");
                return null;
            }

            return section;
        }

        public static IKMPSection? CreateSection(string magic)
        {
            string className = new string(magic.Reverse().ToArray());
            string fullType = $"CTR.Dash.Map.SectionEntries.{className}";
            Type? sectionType = Type.GetType(fullType);
            if (sectionType == null)
                return null;

            object? instance = Activator.CreateInstance(sectionType, magic);
            if (instance is not IKMPSection section)
                return null;

            return section;
        }
    }
}
