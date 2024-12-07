using System.Text;

namespace TapeReader
{
	public class TapeArchive
	{
		/// <summary>
		/// Enum which describes the format of the tape archive.
		/// </summary>
		public enum TapeFormat
		{
			/// <summary>
			/// Unknown format.
			/// </summary>
			UNKNOWN,
			/// <summary>
			/// UNIX V1-V3 tap(1) format.
			/// </summary>
			TAP,
			/// <summary>
			/// UNIX V4-V6 tp(1) format.
			/// </summary>
			TP
		}

		/// <summary>
		/// Enum which describes the state of a block on the tape.
		/// </summary>
		public enum BlockType
		{
			/// <summary>
			/// Block is unused.
			/// </summary>
			FREE,
			/// <summary>
			/// Block is the boot block (but may not contain valid boot code).
			/// </summary>
			BOOT,
			/// <summary>
			/// Block belongs to the archive directory.
			/// </summary>
			DIRECTORY,
			/// <summary>
			/// Block used for data storage.
			/// </summary>
			DATA
		}

		/// <summary>
		/// Structure which represents a file on the tape.
		/// </summary>
		public struct TapeFile
		{
			/// <summary>
			/// Path of the file (31 chars max).
			/// </summary>
			public string Path;
			/// <summary>
			/// Access mode of the file.
			/// </summary>
			public ushort Mode;
			/// <summary>
			/// User (owner) of the file.
			/// </summary>
			public ushort Uid;
			/// <summary>
			/// Group of the file.
			/// </summary>
			public ushort Gid;
			/// <summary>
			/// Length of the file in bytes (16777215 max).
			/// </summary>
			public int Size;
			/// <summary>
			/// Last modification timestamp of the file in UNIX time.
			/// </summary>
			public uint Time;
			/// <summary>
			/// The content of the file.
			/// </summary>
			public byte[] Data;
			/// <summary>
			/// Potential slack space data associated with the file.
			/// </summary>
			public byte[] Slack;
		}

		/// <summary>
		/// Attempts to guess the format the tape archive is in.
		/// </summary>
		/// <param name="data">The raw tape data.</param>
		/// <returns>An educated guess of the tape archive format.</returns>
		public static TapeFormat GuessFormat(byte[] data)
		{
			if (data.Length < 0x3200)
			{
				return TapeFormat.UNKNOWN;
			}
			using (MemoryStream ms = new MemoryStream(data))
			{
				using (BinaryReader br = new BinaryReader(ms))
				{
					for (int i = 0; i < 192; i++)
					{
						br.BaseStream.Position = 512 + i * 64;
						byte[] record = br.ReadBytes(64);
						if (record[0] != 0 && (record[0x2C] != 0 || record[0x2D] != 0))
						{
							return TapeFormat.TP;
						}
					}
					return TapeFormat.TAP;
				}
			}
		}

		/// <summary>
		/// Whether or not loading the tape archive produced warnings.
		/// </summary>
		public bool HasWarning { get; private set; } = false;

		private byte[] _tapeData;
		private TapeFile[] _tapeFiles;
		private TapeFile[] _slackFiles = [];
		private BlockType[] _tapeUsage;

		/// <summary>
		/// Creates a new instance of a tap(1) or tp(1) UNIX tape archive.
		/// </summary>
		/// <param name="data">The raw tape data.</param>
		/// <param name="fmt">The format of the tape.</param>
		/// <param name="epoch">The epoch used when creating the tape, used only if tape format is TAP.</param>
		/// <param name="repair">Whether or not to attempt repair V4 timestamps and truncated access modes.</param>
		public TapeArchive(byte[] data, TapeFormat fmt, int epoch = 1970, bool repair = false)
		{
			if (data.Length < 0x3200)
			{
				throw new InvalidDataException("Invalid tape archive.");
			}

			_tapeData = data;
			_tapeUsage = new BlockType[(_tapeData.Length + 511) / 512];
			using (MemoryStream ms = new MemoryStream(_tapeData))
			{
				using (BinaryReader br = new BinaryReader(ms))
				{
					_tapeFiles = LoadTape(br, fmt, epoch, repair);
				}
			}
		}

		/// <summary>
		/// Gets all files in the tape archive.
		/// </summary>
		/// <returns>Array of TapeFile structures.</returns>
		public TapeFile[] GetFiles()
		{
			return _tapeFiles;
		}

		/// <summary>
		/// Gets the usage map of the tape.
		/// </summary>
		/// <returns>The usage map as a BlockType array.</returns>
		public BlockType[] GetUsageMap() => _tapeUsage;

		/// <summary>
		/// Generates a tarball for the slack space data as well as unused tape blocks.
		/// </summary>
		/// <returns>Tarball archive of the slack space data and unused blocks.</returns>
		public byte[] GetSlackTar() => MakeTar(_slackFiles);

		/// <summary>
		/// Converts the current tape archive to its string representation.
		/// </summary>
		/// <returns>The string representation of the tape archive - a file list.</returns>
		public override string ToString() => ListDirectory(_tapeFiles);

		/// <summary>
		/// Returns the raw tape data.
		/// </summary>
		/// <returns>The raw tape data as byte array.</returns>
		public byte[] ToArray() => _tapeData;

		/// <summary>
		/// Converts the tape to POSIX.1-1988 USTAR.
		/// </summary>
		/// <returns>The converted tar archive as byte array.</returns>
		public byte[] ToTar(bool convPath = false) => MakeTar(_tapeFiles, convPath);

		private TapeFile[] LoadTape(BinaryReader br, TapeFormat fmt, int epoch, bool repair)
		{
			// The list of files in the tape archive.
			List<TapeFile> files = new List<TapeFile>();

			// The list of files to investigate - boot block, bad/deleted directories,
			// slack space data and unused blocks.
			List<TapeFile> slackFiles = new List<TapeFile>();

			// Load in the boot block and mark it as used.
			MarkBootBlockUsed();
			br.BaseStream.Position = 0;
			slackFiles.Add(CreateSimpleFile("boot.bin", br.ReadBytes(512)));

			// Mark all directory blocks as used.
			MarkDirBlocksUsed();

			// Read all directories.
			for (int i = 0; i < 192; i++)
			{
				byte[] dir = ReadDir(br);

				if (fmt == TapeFormat.TAP)
				{
					string name = ByteToStr(TrimPath(br.ReadBytes(32)));
					byte mode = br.ReadByte();
					byte uid = br.ReadByte();
					ushort size = br.ReadUInt16(); // LE
					ushort timehi = br.ReadUInt16(); // LE
					ushort timelo = br.ReadUInt16(); // LE
					uint time = (((uint)timehi) << 16) | timelo;
					ushort location = br.ReadUInt16(); // LE
					byte[] reserved = br.ReadBytes(20);
					ushort checksum = br.ReadUInt16(); // LE
					if (name != "" && name[0] != '\0')
					{
						if (!CheckDir(dir))
						{
							Warning($"Warning: Directory entry {i} checksum mismatch.");
							slackFiles.Add(CreateSimpleFile($"bad_dir/dir{i:D3}.bin", dir));
						}
						MarkFileBlocksUsed(location, size);
						bool newdir = false;
						if ((mode & 0b11000000) != 0)
						{
							newdir = true;
							if (!repair)
							{
								Warning($"Warning: The file {name} was likely written by UNIX V4+, try -r.");
							}
							else
							{
								Warning($"Warning: Attempted to restore UNIX V4+ timestamp and access mode for {name}.");
							}
						}
						files.Add(new TapeFile()
						{
							Path = name,
							Mode = newdir ? RepairMode(mode) : ConvMode(mode),
							Uid = uid,
							Gid = 0,
							Size = size,
							Time = newdir ? time : ConvTime(time, epoch),
							Data = ReadFile(br, location, size),
							Slack = ReadSlack(br, location, size)
						});
					}
					else if (!dir.All(b => b == 0))
					{
						Warning($"Warning: Unused directory entry {i} not empty - maybe deleted file?");
						slackFiles.Add(CreateSimpleFile($"del_dir/dir{i:D3}.bin", dir));
					}
				}
				else if (fmt == TapeFormat.TP)
				{
					string name = ByteToStr(TrimPath(br.ReadBytes(32)));
					ushort mode = br.ReadUInt16(); // LE
					byte uid = br.ReadByte();
					byte gid = br.ReadByte();
					byte res = br.ReadByte();
					int size = br.ReadByte() << 16;
					size |= br.ReadUInt16(); // LE
					ushort timehi = br.ReadUInt16(); // LE
					ushort timelo = br.ReadUInt16(); // LE
					uint time = (((uint)timehi) << 16) | timelo;
					ushort location = br.ReadUInt16(); // LE
					byte[] reserved = br.ReadBytes(16);
					ushort checksum = br.ReadUInt16(); // LE
					if (name != "" && name[0] != '\0')
					{
						// If the string is not empty and does not start with a NUL, then
						// it's a valid directory entry.
						if (!CheckDir(dir))
						{
							// Check the checksum of the directory, if checksum doesn't match,
							// it's probably corrupt, so add it to the list of files to investigate.
							Warning($"Warning: Directory entry {i} checksum mismatch.");
							slackFiles.Add(CreateSimpleFile($"bad_dir/dir{i:D3}.bin", dir));
						}
						MarkFileBlocksUsed(location, size);
						files.Add(new TapeFile()
						{
							Path = name,
							Mode = mode,
							Uid = uid,
							Gid = gid,
							Size = size,
							Time = time,
							Data = ReadFile(br, location, size),
							Slack = ReadSlack(br, location, size)
						});
					}
					else if (!dir.All(b => b == 0))
					{
						// Check if all bytes of the directory are zero. If not, it's a potentially
						// deleted file, so add it to the list of files to investigate.
						Warning($"Warning: Unused directory entry {i} not empty - maybe deleted file?");
						slackFiles.Add(CreateSimpleFile($"del_dir/dir{i:D3}.bin", dir));
					}
				}
				else
				{
					// We only support tap(1) and tp(1) tape archives.
					throw new NotSupportedException("The specified tape archive format is not supported.");
				}
			}

			// Process slack space data (do it after the directories so they come out together in the tarball).
			for (int i = 0; i < files.Count; i++)
			{
				slackFiles.Add(CreateSimpleFile($"slack/{i:D3}.bin", files[i].Slack));
			}

			// Process the unused blocks.
			for (int i = 0; i < _tapeUsage.Length; i++)
			{
				if (_tapeUsage[i] == BlockType.FREE)
				{
					int numBlocks = 0;
					int filling = (512 - (_tapeData.Length % 512)) % 512;
					for (int j = i + 1; j < _tapeUsage.Length; j++)
					{
						if (_tapeUsage[j] != BlockType.FREE)
						{
							numBlocks = j - i;
							break;
						}
					}
					if (numBlocks == 0)
					{
						numBlocks = _tapeUsage.Length - i;
					}
					br.BaseStream.Position = i * 512;
					byte[] dat = br.ReadBytes(numBlocks * 512 - filling);
					slackFiles.Add(CreateSimpleFile("block_" + i.ToString($"X{(_tapeUsage.Length - 1).ToString("X").Length}"), dat));
					i += numBlocks;
				}
			}

			_slackFiles = slackFiles.ToArray();
			return files.ToArray();
		}

		private static bool CheckDir(byte[] dir)
		{
			ushort csum = 0;
			for (int i = 0; i < 64; i += 2)
			{
				csum += (ushort)((dir[i + 1] << 8) | dir[i]);
			}
			return csum == 0;
		}

		private static byte[] ReadDir(BinaryReader br)
		{
			long pos = br.BaseStream.Position;
			byte[] result = br.ReadBytes(64);
			br.BaseStream.Position = pos;
			return result;
		}

		private static string ListDirectory(TapeFile[] files)
		{
			int maxUser = 0;
			int maxGroup = 0;
			int maxSize = 0;
			int maxPath = 0;
			foreach (TapeFile f in files)
			{
				if (f.Uid > maxUser)
				{
					maxUser = f.Uid;
				}
				if (f.Gid > maxGroup)
				{
					maxGroup = f.Gid;
				}
				if (f.Size > maxSize)
				{
					maxSize = f.Size;
				}
				if (f.Path.Length > maxPath)
				{
					maxPath = f.Path.Length;
				}
			}
			int userWidth = Math.Max(maxUser.ToString().Length, 3);
			int groupWidth = Math.Max(maxGroup.ToString().Length, 3);
			int sizeWidth = Math.Max(maxSize.ToString().Length, 4);
			int pathWidth = Math.Max(maxPath, 4);
			string result = $"Mode       {"UID".PadLeft(userWidth)} {"GID".PadLeft(groupWidth)} {"Size".PadLeft(sizeWidth)} Date                Name\n" +
				$"---------- {new string('-', userWidth)} {new string('-', groupWidth)} {new string('-', sizeWidth)} ------------------- {new string('-', pathWidth)}\n";
			foreach (TapeFile f in files)
			{
				string mode = GetModeString(f.Mode);
				string user = f.Uid.ToString().PadLeft(userWidth);
				string group = f.Gid.ToString().PadLeft(groupWidth);
				string size = f.Size.ToString().PadLeft(sizeWidth);
				string time = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(f.Time).ToString("yyyy-MM-dd HH:mm:ss");
				string path = f.Path;
				result += $"{mode} {user} {group} {size} {time} {path}\n";
			}
			return result.Substring(0, result.Length - 1); // Strip last LF.
		}

		private static TapeFile CreateSimpleFile(string path, byte[] content) => new TapeFile()
		{
			Path = path,
			Mode = 0x1A4, // The default rw-r--r-- mode.
			Uid = 1000,
			Gid = 1000,
			Size = content.Length,
			Data = content,
			Slack = []
		};

		private static byte[] MakeTar(TapeFile[] files, bool convPath = false)
		{
			byte[] result;
			using (MemoryStream ms = new MemoryStream())
			{
				using (BinaryWriter bw = new BinaryWriter(ms))
				{
					foreach (TapeFile f in files)
					{
						bw.Write(StrToByte((convPath ? ConvPath(f.Path) : f.Path).PadRight(100, '\0')));
						bw.Write(TarInt(f.Mode, 7));
						bw.Write(TarInt(f.Uid, 7));
						bw.Write(TarInt(f.Gid, 7));
						bw.Write(TarInt(f.Size, 11));
						bw.Write(TarInt(f.Time, 11));
						bw.Write(StrToByte("        "));
						bw.Write('0');
						bw.Write(new byte[100]);
						bw.Write(StrToByte("ustar\0"));
						bw.Write(StrToByte("00"));
						bw.Write(new byte[32]);
						bw.Write(new byte[32]);
						bw.Write(TarInt(0, 7));
						bw.Write(TarInt(0, 7));
						bw.Write(new byte[167]);
						long pos = bw.BaseStream.Position;
						bw.BaseStream.Position -= 512;
						byte[] hdr = new byte[512];
						bw.BaseStream.Read(hdr, 0, 512);
						uint sum = 0;
						foreach (byte b in hdr)
						{
							sum += b;
						}
						bw.BaseStream.Position = pos - 512 + 148;
						bw.Write(TarInt(sum, 6));
						bw.BaseStream.Position = pos;
						bw.Write(f.Data);
						if ((f.Size % 512) != 0)
						{
							bw.Write(new byte[512 - (f.Size % 512)]);
						}
					}
					bw.Write(new byte[1024]);
				}
				result = ms.ToArray();
			}
			return result;
		}

		private static string GetModeString(ushort mode)
		{
			string result = "-";
			result += ((mode & 0x100) != 0) ? "r" : "-";
			result += ((mode & 0x080) != 0) ? "w" : "-";
			if ((mode & 0x800) != 0)
			{
				// SUID.
				result += ((mode & 0x040) != 0) ? "s" : "S";
			}
			else
			{
				result += ((mode & 0x040) != 0) ? "x" : "-";
			}
			result += ((mode & 0x020) != 0) ? "r" : "-";
			result += ((mode & 0x010) != 0) ? "w" : "-";
			if ((mode & 0x400) != 0)
			{
				// SGID.
				result += ((mode & 0x008) != 0) ? "s" : "S";
			}
			else
			{
				result += ((mode & 0x008) != 0) ? "x" : "-";
			}
			result += ((mode & 0x004) != 0) ? "r" : "-";
			result += ((mode & 0x002) != 0) ? "w" : "-";
			result += ((mode & 0x001) != 0) ? "x" : "-";
			return result;
		}

		private void MarkBootBlockUsed()
		{
			_tapeUsage[0] = BlockType.BOOT;
		}

		private void MarkDirBlocksUsed()
		{
			for (int i = 0; i < 24; i++)
			{
				_tapeUsage[i + 1] = BlockType.DIRECTORY;
			}
		}

		private void MarkFileBlocksUsed(ushort block, int size)
		{
			for (int i = 0; i < (size + 511) / 512; i++)
			{
				_tapeUsage[block + i] = BlockType.DATA;
			}
		}

		private static byte[] ReadFile(BinaryReader br, ushort block, int size)
		{
			long pos = br.BaseStream.Position;
			br.BaseStream.Position = (long)block * 512;
			byte[] result = br.ReadBytes(size);
			br.BaseStream.Position = pos;
			return result;
		}

		private static byte[] ReadSlack(BinaryReader br, ushort block, int size)
		{
			if ((size % 512) == 0)
			{
				return [];
			}
			long pos = br.BaseStream.Position;
			br.BaseStream.Position = (long)block * 512 + size;
			byte[] result = br.ReadBytes(512 - (size % 512));
			br.BaseStream.Position = pos;
			return result;
		}

		private static byte[] TarInt(uint num, int digits)
		{
			string mode = Convert.ToString(num, 8).PadLeft(digits, '0');
			return StrToByte(mode + "\0");
		}

		private static byte[] TarInt(int num, int digits)
		{
			string mode = Convert.ToString(num, 8).PadLeft(digits, '0');
			return StrToByte(mode + "\0");
		}

		private static string ByteToStr(byte[] b)
		{
			return Encoding.ASCII.GetString(b);
		}

		private static byte[] StrToByte(string s)
		{
			return Encoding.ASCII.GetBytes(s);
		}

		private static string ConvPath(string path)
		{
			if (path.StartsWith("/"))
			{
				return path.Substring(1);
			}
			if (path.StartsWith("./"))
			{
				return path.Substring(2);
			}
			return path;
		}

		private static uint ConvTime(uint time, int epoch)
		{
			DateTime zero = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
			uint result = time / 60;
			DateTime final = new DateTime(epoch, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(result);
			TimeSpan t = final - zero;
			return (uint)t.TotalSeconds;
		}

		private static ushort RepairMode(byte mode)
		{
			ushort result = mode;
			result &= 0xFF;
			result |= 0x100;
			return result;
		}

		private static ushort ConvMode(ushort mode)
		{
			// tap(1) file mode flags:
			//     0x01 - W OTHER
			//     0x02 - R OTHER
			//     0x04 - W OWNER
			//     0x08 - R OWNER
			//     0x10 - X
			//     0x20 - SUID

			// tar(1) file mode flags:
			//     0x001 - TOEXEC
			//     0x002 - TOWRITE
			//     0x004 - TOREAD
			//     0x008 - TGEXEC
			//     0x010 - TGWRITE
			//     0x020 - TGREAD
			//     0x040 - TUEXEC
			//     0x080 - TUWRITE
			//     0x100 - TUREAD
			//     0x200 - TSVTX
			//     0x400 - TSGID
			//     0x800 - TSUID

			ushort result = 0;
			if ((mode & 0x01) != 0) // W OTHER
			{
				result |= 0x02; // TOWRITE
				result |= 0x10; // TGWRITE
			}
			if ((mode & 0x02) != 0) // R OTHER
			{
				result |= 0x04; // TOREAD
				result |= 0x20; // TGREAD
			}
			if ((mode & 0x04) != 0) // W OWNER
			{
				result |= 0x80; // TUWRITE
			}
			if ((mode & 0x08) != 0) // R OWNER
			{
				result |= 0x100; // TUREAD
			}
			if ((mode & 0x10) != 0) // X
			{
				result |= 0x01; // TOEXEC
				result |= 0x08; // TGEXEC
				result |= 0x40; // TUEXEC
			}
			if ((mode & 0x20) != 0) // SUID
			{
				result |= 0x800; // TSUID
			}
			return result;
		}

		private static byte[] TrimPath(byte[] path)
		{
			Array.Resize(ref path, Array.FindLastIndex(path, b => b != 0) + 1);
			return path;
		}

		private void Warning(string format, params object?[] args)
		{
			HasWarning = true;
			WriteErrorLine(ConsoleColor.Cyan, format, args);
		}

		private static void Error(string format, params object?[] args)
		{
			WriteErrorLine(ConsoleColor.Red, format, args);
		}

		private static void WriteErrorLine(ConsoleColor color, string format, params object?[] args)
		{
			ConsoleColor fc = Console.ForegroundColor;
			Console.ForegroundColor = color;
			Console.Error.WriteLine(format, args);
			Console.ForegroundColor = fc;
		}
	}

	internal class Program
	{
		private static TapeArchive.TapeFormat ParseFormat(string fmt)
		{
			fmt = fmt.Trim();
			switch (fmt.ToLower())
			{
				case "tap":
					return TapeArchive.TapeFormat.TAP;
				case "tp":
					return TapeArchive.TapeFormat.TP;
				default:
					Error($"Error: Invalid tape format \"{fmt}\".");
					return TapeArchive.TapeFormat.UNKNOWN;
			}
		}

		private static int ParseEpoch(string epoch)
		{
			epoch = epoch.Trim();
			try
			{
				int result = int.Parse(epoch);
				if (result < 1970 || result > 1973)
				{
					Error("Error: Epoch must be 1970 - 1973.");
					return 0;
				}
				return result;
			}
			catch (Exception)
			{
				Error($"Error: Invalid epoch \"{epoch}\".");
				return 0;
			}
		}

		static void Main(string[] args)
		{
			if (args.Length < 1)
			{
				Console.WriteLine("TapeReader [-l] [-c] [-f format] [-e epoch] [-s slack-file] <tape-file> [tar-file]\n" +
					"    -l  List all files in the tape archive.\n" +
					"    -c  Convert the tape archive to POSIX.1-1988 USTAR tar(1) format.\n" +
					"    -u  Print usage information and block map of the tape.\n" +
					"    -r  Attempt to recognize and repair access mode of files written by tap(1) under UNIX V4 or later.\n" +
					"    -a  Convert from absolute paths to relative path and strip ./ from all paths.\n" +
					"    -s  Dump all slack space data and unused blocks to a tar(1) archive.\n" +
					"    -f  Specify the format of the tape archive. Valid formats are:\n" +
					"          TAP - tap(1) format created by UNIX V1 - V3\n" +
					"          TP  - tp(1) format created by UNIX V4 - V6\n" +
					"    -e  Specify the epoch for tap(1) archives. Valid epoches are:\n" +
					"          1970, 1971, 1972, 1973");
				return;
			}

			bool error = false;
			bool warning = false;
			bool list = false;
			bool convert = false;
			bool usage = false;
			bool dump = false;
			bool repair = false;
			bool torel = false;
			string? tap = null;
			string? tar = null;
			string? slack = null;
			TapeArchive.TapeFormat fmt = TapeArchive.TapeFormat.UNKNOWN;
			int epoch = 0;

			for (int i = 0; i < args.Length; i++)
			{
				if (args[i] == "-l" || args[i] == "/l")
				{
					list = true;
				}
				else if (args[i] == "-c" || args[i] == "/c")
				{
					convert = true;
				}
				else if (args[i] == "-u" || args[i] == "/u")
				{
					usage = true;
				}
				else if (args[i] == "-r" || args[i] == "/r")
				{
					repair = true;
				}
				else if (args[i] == "-a" || args[i] == "/a")
				{
					torel = true;
				}
				else if (args[i].StartsWith("-f") || args[i].StartsWith("/f"))
				{
					string s = args[i].Substring(2);
					if (s.Length != 0 && s[0] == '=')
					{
						s = s.Substring(1);
					}
					if (s != string.Empty)
					{
						fmt = ParseFormat(s);
						error = (fmt != TapeArchive.TapeFormat.UNKNOWN) ? error : true;
					}
					else if (i < args.Length - 1)
					{
						i++;
						fmt = ParseFormat(args[i]);
						error = (fmt != TapeArchive.TapeFormat.UNKNOWN) ? error : true;
					}
					else
					{
						Error("Error: -t must be followed by tape format.");
						error = true;
					}
				}
				else if (args[i].StartsWith("-e") || args[i].StartsWith("/e"))
				{
					string s = args[i].Substring(2);
					if (s.Length != 0 && s[0] == '=')
					{
						s = s.Substring(1);
					}
					if (s != string.Empty)
					{
						epoch = ParseEpoch(s);
						error = (epoch != 0) ? error : true;
					}
					else if (i < args.Length - 1)
					{
						i++;
						epoch = ParseEpoch(args[i]);
						error = (epoch != 0) ? error : true;
					}
					else
					{
						Error("Error: -e must be followed by epoch year.");
						error = true;
					}
				}
				else if (args[i].StartsWith("-s") || args[i].StartsWith("/s"))
				{
					dump = true;
					string s = args[i].Substring(2);
					if (s.Length != 0 && s[0] == '=')
					{
						s = s.Substring(1);
					}
					if (s != string.Empty)
					{
						slack = s.Trim();
					}
					else if (i < args.Length - 1)
					{
						i++;
						slack = args[i].Trim();
					}
					else
					{
						Error("Error: -t must be followed by tape format.");
						error = true;
					}
				}
				else
				{
					if (tap == null)
					{
						tap = args[i];
					}
					else if (tar == null)
					{
						tar = args[i];
					}
				}
			}

			if (error)
			{
				return;
			}

			if (tap == null)
			{
				Error("Error: No tape file provided.");
				return;
			}

			if (convert && tar == null)
			{
				Error("Error: No output tar(1) file specified.");
				return;
			}

			if (dump && slack == null)
			{
				Error("Error: No slack space tar(1) file specified.");
				return;
			}

			byte[] tapdat;

			try
			{
				tapdat = File.ReadAllBytes(tap);
			}
			catch (Exception)
			{
				Error($"Error: Failed to read \"{tap}\".");
				return;
			}

			if (fmt == TapeArchive.TapeFormat.UNKNOWN)
			{
				fmt = TapeArchive.GuessFormat(tapdat);
				warning = true;
				Warning($"Warning: No tape format given, using guessed format - {
					fmt switch
					{
						TapeArchive.TapeFormat.TAP => "tap(1)",
						TapeArchive.TapeFormat.TP => "tp(1)",
						_ => "UNKNOWN"
					}
					}.");
			}

			if (epoch == 0 && fmt == TapeArchive.TapeFormat.TAP)
			{
				epoch = 1972;
				warning = true;
				Warning($"Warning: No epoch given for tap(1) archive, using guessed epoch - {epoch}.");
			}
			else if (epoch != 0 && fmt == TapeArchive.TapeFormat.TP)
			{
				warning = true;
				Warning($"Warning: Epoch of {epoch} ignored for tp(1) archive.");
			}

			if (repair && fmt == TapeArchive.TapeFormat.TP)
			{
				warning = true;
				Warning($"Warning: -r ignored for tp(1) archive.");
			}

			if (warning)
			{
				Warning("");
			}

			TapeArchive tape;
			try
			{
				tape = new TapeArchive(tapdat, fmt, epoch, repair);
			}
			catch (Exception e)
			{
				Error($"Error: {e.Message}");
				return;
			}

			if (tape.HasWarning)
			{
				Warning("");
			}

			if (list)
			{
				Console.WriteLine(tape.ToString());
			}

			if (usage)
			{
				if (list)
				{
					Console.WriteLine();
				}

				TapeArchive.BlockType[] usageData = tape.GetUsageMap();
				int numrows = (usageData.Length + 15) / 16;
				int hexlen = numrows.ToString("X").Length;
				int numFree = usageData.Count(b => b == TapeArchive.BlockType.FREE);
				int numUsed = usageData.Length - numFree;

				Console.WriteLine($"{usageData.Length} blocks, {numUsed} ({(double)numUsed / usageData.Length:P2}) used, {numFree} ({(double)numFree / usageData.Length:P2}) free.");
				Console.WriteLine("B = boot; D = directroy;\n. = free; X = file data;\n");

				Console.WriteLine($"{new string(' ', hexlen)}|0123456789ABCDEF\n{new string('-', hexlen)}+----------------");
				for (int i = 0; i < numrows; i++)
				{
					Console.Write(i.ToString("X").PadLeft(hexlen, '0') + "|");
					for (int j = 0; j < ((i == numrows - 1) ? (usageData.Length % 16) : 16); j++)
					{
						Console.Write($"{usageData[i * 16 + j] switch
						{
							TapeArchive.BlockType.FREE => ".",
							TapeArchive.BlockType.BOOT => "B",
							TapeArchive.BlockType.DIRECTORY => "D",
							TapeArchive.BlockType.DATA => "X",
							_ => "?"
						}}");
					}
					Console.WriteLine("");
				}
			}

			if (convert && tar != null)
			{
				try
				{
					File.WriteAllBytes(tar, tape.ToTar(torel));
				}
				catch (Exception)
				{
					Error($"Error: Failed to write \"{tar}\".");
					return;
				}
			}

			if (dump && slack != null)
			{
				try
				{
					File.WriteAllBytes(slack, tape.GetSlackTar());
				}
				catch (Exception)
				{
					Error($"Error: Failed to write \"{slack}\".");
					return;
				}
			}
		}

		private static void Warning(string format, params object?[] args)
		{
			WriteErrorLine(ConsoleColor.Magenta, format, args);
		}

		private static void Error(string format, params object?[] args)
		{
			WriteErrorLine(ConsoleColor.Red, format, args);
		}

		private static void WriteErrorLine(ConsoleColor color, string format, params object?[] args)
		{
			ConsoleColor fc = Console.ForegroundColor;
			Console.ForegroundColor = color;
			Console.Error.WriteLine(format, args);
			Console.ForegroundColor = fc;
		}
	}
}
