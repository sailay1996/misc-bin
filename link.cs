/***
 * https://pastebin.com/raw/d1phQyXR 
 ***/
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace de.usd.SharpLink
{

    [StructLayout(LayoutKind.Sequential)]
    struct KEY_VALUE_INFORMATION
    {
        public uint TitleIndex;
        public uint Type;
        public uint DataLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x400)]
        public byte[] Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MOUNT_POINT_REPARSE_BUFFER
    {
        public ushort SubstituteNameOffset;
        public ushort SubstituteNameLength;
        public ushort PrintNameOffset;
        public ushort PrintNameLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x3FF0)]
        public byte[] PathBuffer;
    }

    [StructLayout(LayoutKind.Explicit)]
    struct REPARSE_DATA_BUFFER
    {
        [FieldOffset(0)] public uint ReparseTag;
        [FieldOffset(4)] public ushort ReparseDataLength;
        [FieldOffset(6)] public ushort Reserved;
        [FieldOffset(8)] public MOUNT_POINT_REPARSE_BUFFER MountPointBuffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES : IDisposable
    {
        public int Length;
        public IntPtr RootDirectory;
        private IntPtr objectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;

        public OBJECT_ATTRIBUTES(string name, uint attrs)
        {
            Length = 0;
            RootDirectory = IntPtr.Zero;
            objectName = IntPtr.Zero;
            Attributes = attrs;
            SecurityDescriptor = IntPtr.Zero;
            SecurityQualityOfService = IntPtr.Zero;

            Length = Marshal.SizeOf(this);
            ObjectName = new UNICODE_STRING(name);
        }

        public UNICODE_STRING ObjectName
        {
            get
            {
                return (UNICODE_STRING)Marshal.PtrToStructure(
                 objectName, typeof(UNICODE_STRING));
            }

            set
            {
                bool fDeleteOld = objectName != IntPtr.Zero;
                if (!fDeleteOld)
                    objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                Marshal.StructureToPtr(value, objectName, fDeleteOld);
            }
        }

        public void Dispose()
        {
            if (objectName != IntPtr.Zero)
            {
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }
        }
    }

    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Buffer;

        public UNICODE_STRING(string str)
        {
            Length = (ushort)(str.Length * 2);
            MaximumLength = (ushort)((str.Length * 2) + 1);
            Buffer = str;
        }
    }


    public interface ILink
    {
        // open the underlying link
        void Open();

        // close the underlying link
        void Close();

        // print the current link status to stdout
        void Status();

        // enforce closing the link
        void ForceClose();

        // tell the link whether it should stay alive after the object is cleaned up
        void KeepAlive(bool value);
    }


    public class LinkGroup
    {
        // Links stored within the LinkGroup
        private HashSet<ILink> links;

 
        public LinkGroup()
        {
            links = new HashSet<ILink>();
        }

 
        public void AddLink(ILink link)
        {
            links.Add(link);
        }


        public void AddSymlink(string path, string target)
        {
            AddSymlink(path, target, false);
        }


        public void AddSymlink(string path, string target, bool keepAlive)
        {
            links.Add(new Symlink(path, target, keepAlive));
        }


        public void AddRegistryLink(string path, string target)
        {
            AddRegistryLink(path, target, false);
        }


        public void AddRegistryLink(string key, string target, bool keepAlive)
        {
            links.Add(new RegistryLink(key, target, keepAlive));
        }


        public void KeepAlive()
        {
            KeepAlive(true);
        }


        public void KeepAlive(bool value)
        {
            foreach (ILink link in links)
                link.KeepAlive(value);
        }

   
        public void Open()
        {
            foreach (ILink link in links)
                link.Open();
        }

     
        public void Close()
        {
            foreach (ILink link in links)
                link.Close();
        }

     
        public void ForceClose()
        {
            foreach (ILink link in links)
                link.ForceClose();
        }


        public void Clear()
        {
            links.Clear();
        }


        public ILink[] GetLinks()
        {
            return links.ToArray<ILink>();
        }


        public void Status()
        {
            Console.WriteLine("[+] LinkGroup contains {0} link(s):", links.Count);

            foreach (ILink link in links)
            {
                Console.WriteLine("[+]");
                link.Status();
            }
        }
    }


    public class Symlink : ILink
    {
        // file system path the symlink is created in
        private string path;

        // file system path the symlink should point to
        private string target;

        // associated Junction object (assigned when opening the link - may be null)
        private Junction junction;

        // associated DosDevice object (assigned when opening the link - may be null)
        private DosDevice dosDevice;

        // whether to keep the associated Junction and DosDevice alive after the object is removed
        private bool keepAlive;


        public Symlink(string path, string target) : this(path, target, false) { }


        public Symlink(string path, string target, bool keepAlive)
        {
            this.path = Path.GetFullPath(path);
            this.target = Path.GetFullPath(target);

            this.junction = null;
            this.dosDevice = null;
            this.keepAlive = keepAlive;
        }


        public void KeepAlive()
        {
            KeepAlive(true);
        }


        public void KeepAlive(bool value)
        {
            this.keepAlive = true;

            if (junction != null)
                junction.KeepAlive(value);

            if (dosDevice != null)
                dosDevice.KeepAlive(value);
        }

 
        public Junction GetJunction()
        {
            return junction;
        }


        public DosDevice GetDosDevice()
        {
            return dosDevice;
        }


        public void Status()
        {
            Console.WriteLine("[+] Link type: File system symbolic link");
            Console.WriteLine("[+] \tLink path: {0}", path);
            Console.WriteLine("[+] \tTarget path: {0}", target);

            Console.WriteLine("[+] \tAssociated Junction: {0}", (junction == null) ? "none" : junction.GetBaseDir());
            Console.WriteLine("[+] \tAssociated DosDevice: {0}", (dosDevice == null) ? "none" : dosDevice.GetName());
        }


        public void Open()
        {
            if (junction != null && dosDevice != null)
            {
                Console.WriteLine("[-] Symlink was already opened. Call the Close function first if you want to reopen.");
                return;
            }

            string linkFile = Path.GetFileName(path);
            string linkDir = Path.GetDirectoryName(path);

            if (String.IsNullOrEmpty(linkDir))
            {
                Console.WriteLine("[-] Symlinks require at least one upper directory (e.g. example\\link)");
                return;
            }

            if (junction == null)
                junction = Junction.Create(linkDir, @"\RPC CONTROL", keepAlive);

            if (dosDevice == null)
                dosDevice = DosDevice.Create(linkFile, target, keepAlive);

            Console.WriteLine("[+] Symlink setup successfully.");
        }


        public void Close()
        {
            if (junction == null && dosDevice == null)
            {
                Console.WriteLine("[!] The current Symlink does not hold ownership on any Junction or DosDevice.");
                Console.WriteLine("[!] Use ForceClose if you really want to close it.");
                return;
            }

            if (junction != null)
                junction.Close();

            if (dosDevice != null)
                dosDevice.Close();

            junction = null;
            dosDevice = null;

            Console.WriteLine("[+] Symlink deleted.");
        }

        public void ForceClose()
        {
            if (junction != null)
                junction.ForceClose();

            if (dosDevice != null)
                dosDevice.ForceClose();

            junction = null;
            dosDevice = null;

            Console.WriteLine("[+] Symlink deleted.");
        }

        public override int GetHashCode()
        {
            return (path + " -> " + target).GetHashCode();
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as Symlink);
        }

        public bool Equals(Symlink other)
        {
            return (path == other.path) && (target == other.target);
        }


        public static Symlink FromFile(string path, string target)
        {
            if (!File.Exists(path))
            {
                Console.WriteLine("[-] Unable to find file: {0}", path);
                return null;
            }

            Console.Write("[?] Delete existing file? (y/N) ");
            ConsoleKey response = Console.ReadKey(false).Key;
            Console.WriteLine();

            if (response == ConsoleKey.Y)
                File.Delete(path);

            return new Symlink(path, target);
        }


        public static LinkGroup FromFolder(string src, string target)
        {
            if (!Directory.Exists(src))
            {
                Console.WriteLine("[-] Unable to find directory: {0}", src);
                return null;
            }

            Console.Write("[?] Delete files in link folder? (y/N) ");
            ConsoleKey response = Console.ReadKey(false).Key;
            Console.WriteLine();

            LinkGroup linkGroup = new LinkGroup();

            foreach (string filename in Directory.EnumerateFiles(src))
            {
                if (response == ConsoleKey.Y)
                    File.Delete(filename);

                linkGroup.AddLink(new Symlink(filename, target));
            }

            return linkGroup;
        }

        public static LinkGroup FromFolderToFolder(string src, string dst)
        {
            if (!Directory.Exists(src))
            {
                Console.WriteLine("[-] Unable to find directory: {0}", src);
                return null;
            }

            if (!Directory.Exists(dst))
            {
                Console.WriteLine("[-] Unable to find directory: {0}", dst);
                return null;
            }

            Console.Write("[?] Delete files in link folder? (y/N) ");
            ConsoleKey response = Console.ReadKey(false).Key;
            Console.WriteLine();

            LinkGroup linkGroup = new LinkGroup();

            foreach (string filename in Directory.EnumerateFiles(src))
            {
                if (response == ConsoleKey.Y)
                    File.Delete(filename);

                linkGroup.AddLink(new Symlink(filename, Path.Combine(dst, Path.GetFileName(filename))));
            }

            return linkGroup;
        }
    }

    public class DosDevice
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool DefineDosDevice(uint dwFlags, string lpDeviceName, string lpTargetPath);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);

        // name of the DosDevice
        private string name;

        // path to the target file on the file system with the \??\ prefix
        private string target;

        // whether the DosDevice was already manually closed
        private bool closed;

        // whether to keep the created DosDevice alive after the object is cleaned up
        private bool keepAlive;

        private const uint DDD_RAW_TARGET_PATH = 0x00000001;
        private const uint DDD_REMOVE_DEFINITION = 0x00000002;
        private const uint DDD_EXACT_MATCH_ON_REMOVE = 0x00000004;
        private const uint DDD_NO_BROADCAST_SYSTEM = 0x00000008;

        private DosDevice(string name, string target, bool keepAlive)
        {
            this.name = name;
            this.target = target;
            this.keepAlive = keepAlive;

            this.closed = false;
        }

 
        ~DosDevice()
        {
            if (!keepAlive && !closed)
                Close();
        }

 
        public string GetTarget()
        {
            return target;
        }

  
        public string GetName()
        {
            return name;
        }


        public void KeepAlive(bool value)
        {
            keepAlive = value;
        }

 
        public void Close()
        {
            Close(name, target);
            closed = true;
        }

 
        public void ForceClose()
        {
            Close(name);
            closed = true;
        }

       
        public static DosDevice Create(string name, string target, bool keepAlive)
        {
            name = PrepareDevicePath(name);
            target = PrepareTargetPath(target);

            string destination = GetTarget(name);

            if (destination != null)
            {
                if (destination == target)
                {
                    Console.WriteLine("[+] DosDevice {0} -> {1} does already exist.", name, target);
                    return null;
                }

                throw new IOException(String.Format("DosDevice {0} does already exist, but points to {0}", name, destination));
            }

            Console.WriteLine("[+] Creating DosDevice: {0} -> {1}", name, target);

            if (DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, name, target) &&
                DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, name, target))
            {
                return new DosDevice(name, target, keepAlive);
            }

            throw new IOException("Unable to create DosDevice.", Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
        }


        public static void Close(string name, string target)
        {
            name = PrepareDevicePath(name);
            target = PrepareTargetPath(target);

            string destination = GetTarget(name);

            if (destination == null)
            {
                Console.WriteLine("[+] DosDevice {0} -> {1} was already closed.", name, target);
                return;
            }

            if (destination != target)
            {
                Console.WriteLine("[!] DosDevice {0} is pointing to {1}.", name, destination);
                Console.WriteLine("[!] Treating as closed.");
                return;
            }

            Console.WriteLine("[+] Deleting DosDevice: {0} -> {1}", name, target);

            DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION |
                            DDD_EXACT_MATCH_ON_REMOVE, name, target);

            DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION |
                            DDD_EXACT_MATCH_ON_REMOVE, name, target);
        }

 
        public static void Close(string name)
        {
            name = PrepareDevicePath(name);

            Console.WriteLine("[+] Deleting DosDevice: {0}", name);

            DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION |
                            DDD_EXACT_MATCH_ON_REMOVE, name, null);

            DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION |
                            DDD_EXACT_MATCH_ON_REMOVE, name, null);
        }


        public static string GetTarget(string name)
        {
            name = PrepareDevicePath(name);

            StringBuilder pathInformation = new StringBuilder(250);
            uint result = QueryDosDevice(name, pathInformation, 250);

            if (result == 0)
                return null;

            return pathInformation.ToString();
        }


        private static string PrepareDevicePath(string path)
        {
            string prefix = @"Global\GLOBALROOT\RPC CONTROL\";

            if (path.StartsWith(prefix))
                return path;

            return prefix + path;
        }


        private static string PrepareTargetPath(string path)
        {
            string prefix = @"\??\";

            if (path.StartsWith(prefix))
                return path;

            return prefix + path;
        }
    }


    public class Junction
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile(string filename, FileAccess access, FileShare share, IntPtr securityAttributes, FileMode fileMode, uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, IntPtr lpInBuffer, int nInBufferSize, IntPtr lpOutBuffer, int nOutBufferSize, out int lpBytesReturned, IntPtr lpOverlapped);

        // base directory the junction starts from
        private string baseDir;

        // target directory the junction is pointing to
        private string targetDir;

        // whether to keep the associated Junction alive when the object is cleaned up
        private bool keepAlive;

        // whether the DosDevice was already closed manually
        private bool closed;

        // whether the junction directory was created by this instance
        private bool dirCreated;

        private const int FSCTL_SET_REPARSE_POINT = 0x000900A4;
        private const int FSCTL_GET_REPARSE_POINT = 0x000900A8;
        private const int FSCTL_DELETE_REPARSE_POINT = 0x000900AC;
        private const uint ERROR_NOT_A_REPARSE_POINT = 0x80071126;
        private const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;


        private Junction(string baseDir, string targetDir, bool dirCreated, bool keepAlive)
        {
            this.baseDir = baseDir;
            this.targetDir = targetDir;

            this.dirCreated = dirCreated;
            this.keepAlive = keepAlive;

            this.closed = false;
        }


        ~Junction()
        {
            if (!keepAlive && !closed)
                Close();
        }


        public string GetBaseDir()
        {
            return baseDir;
        }


        public string GetTargetDir()
        {
            return targetDir;
        }


        public void KeepAlive(bool value)
        {
            keepAlive = value;
        }


        public void Close()
        {
            Close(baseDir, targetDir);
            closed = true;

            if (Directory.Exists(baseDir) && dirCreated)
                Directory.Delete(baseDir);
        }


        public void ForceClose()
        {
            Close(baseDir);
            closed = true;

            if (Directory.Exists(baseDir) && dirCreated)
                Directory.Delete(baseDir);
        }


        public static Junction Create(string baseDir, string targetDir, bool keepAlive)
        {
            bool dirCreated = false;

            if (!Directory.Exists(baseDir))
            {
                Directory.CreateDirectory(baseDir);
                dirCreated = true;
            }

            string existingTarget = GetTarget(baseDir);

            if (existingTarget != null)
            {
                if (existingTarget == targetDir)
                {
                    Console.WriteLine("[+] Junction {0} -> {1} does already exist.", baseDir, targetDir);
                    return null;
                }

                throw new IOException(String.Format("Junction {0} exists, but points to {1}", baseDir, existingTarget));
            }

            DirectoryInfo baseDirInfo = new DirectoryInfo(baseDir);

            if (baseDirInfo.EnumerateFileSystemInfos().Any())
            {
                Console.Write("[!] Junction directory {0} isn't empty. Delete files? (y/N) ", baseDir);
                ConsoleKey response = Console.ReadKey(false).Key;
                Console.WriteLine();

                if (response == ConsoleKey.Y)
                {
                    foreach (FileInfo file in baseDirInfo.EnumerateFiles())
                    {
                        file.Delete();
                    }
                    foreach (DirectoryInfo dir in baseDirInfo.EnumerateDirectories())
                    {
                        dir.Delete(true);
                    }
                }

                else
                    throw new IOException("Junction directory needs to be empty.");
            }

            Console.WriteLine("[+] Creating Junction: {0} -> {1}", baseDir, targetDir);

            using (SafeFileHandle safeHandle = OpenReparsePoint(baseDir))
            {
                var targetDirBytes = Encoding.Unicode.GetBytes(targetDir);
                var reparseDataBuffer = new REPARSE_DATA_BUFFER
                {
                    ReparseTag = IO_REPARSE_TAG_MOUNT_POINT,
                    ReparseDataLength = (ushort)(targetDirBytes.Length + 12),
                    MountPointBuffer = new MOUNT_POINT_REPARSE_BUFFER
                    {
                        SubstituteNameOffset = 0,
                        SubstituteNameLength = (ushort)targetDirBytes.Length,
                        PrintNameOffset = (ushort)(targetDirBytes.Length + 2),
                        PrintNameLength = 0,
                        PathBuffer = new byte[0x3ff0]
                    }
                };

                Array.Copy(targetDirBytes, reparseDataBuffer.MountPointBuffer.PathBuffer, targetDirBytes.Length);

                var inBufferSize = Marshal.SizeOf(reparseDataBuffer);
                var inBuffer = Marshal.AllocHGlobal(inBufferSize);

                try
                {
                    Marshal.StructureToPtr(reparseDataBuffer, inBuffer, false);

                    int bytesReturned;
                    var result = DeviceIoControl(safeHandle.DangerousGetHandle(), FSCTL_SET_REPARSE_POINT,
                        inBuffer, targetDirBytes.Length + 20, IntPtr.Zero, 0, out bytesReturned, IntPtr.Zero);

                    if (!result)
                        throw new IOException("Unable to create Junction.", Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));

                    return new Junction(baseDir, targetDir, dirCreated, keepAlive);
                }

                finally
                {
                    Marshal.FreeHGlobal(inBuffer);
                }
            }
        }


        public static void Close(string baseDir, string targetDir)
        {
            string target = GetTarget(baseDir);

            if (target == null)
            {
                Console.WriteLine("[+] Junction was already closed.");
                return;
            }

            else if (target != targetDir)
            {
                Console.WriteLine("[!] Junction {0} points to {1}", baseDir, target);
                Console.WriteLine("[!] Treating as closed.");
                return;
            }

            Close(baseDir);
        }


        public static void Close(string baseDir)
        {
            Console.WriteLine("[+] Removing Junction: {0}", baseDir);

            using (SafeFileHandle safeHandle = OpenReparsePoint(baseDir))
            {
                var reparseDataBuffer = new REPARSE_DATA_BUFFER
                {
                    ReparseTag = IO_REPARSE_TAG_MOUNT_POINT,
                    ReparseDataLength = 0,
                    MountPointBuffer = new MOUNT_POINT_REPARSE_BUFFER
                    {
                        PathBuffer = new byte[0x3ff0]
                    }
                };

                var inBufferSize = Marshal.SizeOf(reparseDataBuffer);
                var inBuffer = Marshal.AllocHGlobal(inBufferSize);

                try
                {
                    Marshal.StructureToPtr(reparseDataBuffer, inBuffer, false);

                    int bytesReturned;
                    var result = DeviceIoControl(safeHandle.DangerousGetHandle(), FSCTL_DELETE_REPARSE_POINT,
                        inBuffer, 8, IntPtr.Zero, 0, out bytesReturned, IntPtr.Zero);

                    if (!result)
                        throw new IOException("Unable to delete Junction!", Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));
                }

                finally
                {
                    Marshal.FreeHGlobal(inBuffer);
                }
            }
        }


        public static string GetTarget(string baseDir)
        {
            if (!Directory.Exists(baseDir))
                return null;

            REPARSE_DATA_BUFFER reparseDataBuffer;

            using (SafeFileHandle fileHandle = OpenReparsePoint(baseDir))
            {
                if (fileHandle.IsInvalid)
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }

                var outBufferSize = Marshal.SizeOf(typeof(REPARSE_DATA_BUFFER));
                var outBuffer = IntPtr.Zero;

                try
                {
                    outBuffer = Marshal.AllocHGlobal(outBufferSize);
                    int bytesReturned;
                    bool success = DeviceIoControl(fileHandle.DangerousGetHandle(), FSCTL_GET_REPARSE_POINT, IntPtr.Zero, 0,
                        outBuffer, outBufferSize, out bytesReturned, IntPtr.Zero);

                    fileHandle.Close();

                    if (!success)
                    {
                        if (((uint)Marshal.GetHRForLastWin32Error()) == ERROR_NOT_A_REPARSE_POINT)
                        {
                            return null;
                        }
                        Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                    }

                    reparseDataBuffer = (REPARSE_DATA_BUFFER)Marshal.PtrToStructure(outBuffer, typeof(REPARSE_DATA_BUFFER));
                }
                finally
                {
                    Marshal.FreeHGlobal(outBuffer);
                }
            }

            if (reparseDataBuffer.ReparseTag != IO_REPARSE_TAG_MOUNT_POINT)
            {
                return null;
            }

            string target = Encoding.Unicode.GetString(reparseDataBuffer.MountPointBuffer.PathBuffer,
                reparseDataBuffer.MountPointBuffer.SubstituteNameOffset, reparseDataBuffer.MountPointBuffer.SubstituteNameLength);

            return target;
        }


        private static SafeFileHandle OpenReparsePoint(string baseDir)
        {
            IntPtr handle = CreateFile(baseDir, FileAccess.Read | FileAccess.Write, FileShare.None, IntPtr.Zero, FileMode.Open,
                                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);

            if (Marshal.GetLastWin32Error() != 0)
                throw new IOException("OpenReparsePoint failed!", Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error()));

            return new SafeFileHandle(handle, true);
        }
    }

    public class RegistryLink : ILink
    {
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        static extern uint NtCreateKey(out IntPtr KeyHandle, uint DesiredAccess, [In] OBJECT_ATTRIBUTES ObjectAttributes, int TitleIndex, [In] string Class, int CreateOptions, out int Disposition);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        static extern uint NtSetValueKey(SafeRegistryHandle KeyHandle, UNICODE_STRING ValueName, int TitleIndex, int Type, byte[] Data, int DataSize);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        static extern uint NtDeleteKey(SafeRegistryHandle KeyHandle);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        static extern uint NtOpenKeyEx(out IntPtr hObject, uint DesiredAccess, [In] OBJECT_ATTRIBUTES ObjectAttributes, int OpenOptions);

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        static extern uint NtQueryValueKey(SafeRegistryHandle KeyHandle, UNICODE_STRING ValueName, uint InformationClass, out KEY_VALUE_INFORMATION ValueInformation, int size, out int sizeRequired);

        enum KEY_VALUE_INFORMATION_CLASS : uint
        {
            KeyValueBasicInformation,
            KeyValueFullInformation,
            KeyValuePartialInformation,
            KeyValueFullInformationAlign64,
            KeyValuePartialInformationAlign64,
            KeyValueLayerInformation,
            MaxKeyValueInfoClass
        }

        private const uint ATTRIBUT_FLAG_OBJ_OPENLINK = 0x00000100;
        private const uint ATTRIBUT_FLAG_CASE_INSENSITIVE = 0x00000040;

        // combines KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_LINK
        private const uint KEY_LINK_ACCESS = 0x0001 | 0x0002 | 0x0020 | 0x00010000;

        // combines KEY_QUERY_VALUE and DELETE
        private const uint KEY_READ_DELETE_ACCESS = 0x0001 | 0x00010000;

        private const int KEY_TYPE_LINK = 0x0000006;
        private const int REG_OPTION_OPEN_LINK = 0x0008;
        private const int REG_OPTION_CREATE_LINK = 0x00000002;
        private const int REG_CREATED_NEW_KEY = 0x00000001;
        private const int REG_OPENED_EXISTING_KEY = 0x00000002;

        private const string regpath = @"\Registry\";

       
        private string key;

       
        private string target;

    
        private bool created;


        private bool keepAlive;

 
        public RegistryLink(string key, string target) : this(key, target, false) { }


        public RegistryLink(string key, string target, bool keepAlive)
        {
            this.key = RegPathToNative(key);
            this.target = RegPathToNative(target);
            this.keepAlive = keepAlive;

            this.created = false;
        }


        ~RegistryLink()
        {
            if (!keepAlive && created)
                Close();
        }


        public void KeepAlive()
        {
            KeepAlive(true);
        }


        public void KeepAlive(bool value)
        {
            keepAlive = value;
        }


        public string GetTarget()
        {
            return target;
        }


        public void Open()
        {
            if (created)
            {
                Console.WriteLine("[!] Link {0} was already opened. Close it before calling Open again.", key);
                return;
            }

            created = CreateLink(key, target);
        }

 
        public void Close()
        {
            if (created)
            {
                DeleteLink(key, target);
                created = false;
                return;
            }

            Console.WriteLine("[!] The current RegistryLink does not hold ownership on {0}", key);
            Console.WriteLine("[!] Use ForceClose if you really want to close it.");
        }


        public void ForceClose()
        {
            DeleteKey(key);
            created = false;
        }


        public void Status()
        {
            Console.WriteLine("[+] Link Type: Registry symbolic link");
            Console.WriteLine("[+] \tLink key: {0}", key);
            Console.WriteLine("[+] \tTarget key: {0}", target);
            Console.WriteLine("[+] \tCreated: {0}", created);
        }


        public override int GetHashCode()
        {
            return (key + " -> " + target).GetHashCode();
        }


        public override bool Equals(object obj)
        {
            return Equals(obj as RegistryLink);
        }


        public bool Equals(RegistryLink other)
        {
            return (key == other.key) && (target == other.target);
        }


        public static bool CreateLink(string key, string target)
        {
            SafeRegistryHandle handle = OpenKey(key);

            if (handle == null)
                handle = CreateLink(key);

            else
            {
                string linkPath = GetLinkTarget(handle);

                if (linkPath == null)
                {
                    Console.Write("[!] Registry key {0} does already exist and is not a symlink. Delete it (y/N)? ", key);
                    ConsoleKey response = Console.ReadKey(false).Key;
                    Console.WriteLine();

                    if (response != ConsoleKey.Y)
                    {
                        handle.Dispose();
                        throw new IOException("Cannot continue without deleting the key.");
                    }

                    DeleteKey(handle, key);
                    handle.Dispose();
                    handle = CreateLink(key);
                }

                else
                {
                    handle.Dispose();

                    if (linkPath == target)
                    {
                        Console.WriteLine("[+] Registry link {0} -> {1} alreday exists.", key, target);
                        return false;
                    }

                    Console.WriteLine("[!] Registry symlink already exists but is pointing to {0}", linkPath);
                    Console.WriteLine("[!] They key is treated as open, but may point to an unintended target.");
                    return false;
                }
            }

            UNICODE_STRING value_name = new UNICODE_STRING("SymbolicLinkValue");
            byte[] data = Encoding.Unicode.GetBytes(target);

            Console.WriteLine("[+] Assigning symlink property pointing to: {0}", target);
            uint status = NtSetValueKey(handle, value_name, 0, KEY_TYPE_LINK, data, data.Length);
            handle.Dispose();

            if (status != 0)
            {
                throw new IOException(String.Format("Failure while linking {0} to {1}. NTSTATUS: {2:X}", key, target, status));
            }

            Console.WriteLine("[+] RegistryLink setup successful!");
            return true;
        }


        public static void DeleteLink(string key, string target)
        {
            string linkTarget = GetLinkTarget(key);

            if (linkTarget == null)
            {
                Console.WriteLine("[!] Registry key {0} is no longer a symlink.", key);
                Console.WriteLine("[!] Not deleting it.");
            }

            else if (linkTarget != target)
            {
                Console.WriteLine("[!] Registry key {0} is pointing to an unexpected target: {1}.", key, linkTarget);
                Console.WriteLine("[!] Not deleting it.");
            }

            else
                DeleteKey(key);
        }


        public static void DeleteKey(string key)
        {
            using (SafeRegistryHandle handle = OpenKey(key))
            {
                if (handle == null)
                    Console.WriteLine("[!] Registry link {0} was already closed.", key);

                else
                    DeleteKey(handle, key);
            }
        }

        public static void CreateKey(string key)
        {
            OBJECT_ATTRIBUTES obj_attr = new OBJECT_ATTRIBUTES(RegPathToNative(key), ATTRIBUT_FLAG_CASE_INSENSITIVE);
            int disposition = 0;

            Console.WriteLine("[+] Creating registry key: {0}", key);

            IntPtr handle;
            uint status = NtCreateKey(out handle, KEY_LINK_ACCESS, obj_attr, 0, null, 0, out disposition);

            if (status != 0)
                throw new IOException(String.Format("Failure while creating registry key: {0}. NTSTATUS: {1:X}", key, status));

            if (disposition == REG_CREATED_NEW_KEY)
                Console.WriteLine("[+] Registry key was successfully created.");

            else if (disposition == REG_OPENED_EXISTING_KEY)
                Console.WriteLine("[!] Registry did already exist.");

            new SafeRegistryHandle(handle, true).Dispose();
        }


        public static string GetLinkTarget(string key)
        {
            using (SafeRegistryHandle handle = OpenKey(key))
            {
                return GetLinkTarget(handle);
            }
        }


        private static string GetLinkTarget(SafeRegistryHandle handle)
        {
            if (handle == null)
                return null;

            KEY_VALUE_INFORMATION record = new KEY_VALUE_INFORMATION
            {
                TitleIndex = 0,
                Type = 0,
                DataLength = 0,
                Data = new byte[0x400]
            };

            int length = 0;
            uint status = NtQueryValueKey(handle, new UNICODE_STRING("SymbolicLinkValue"), (uint)KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation,
                                     out record, Marshal.SizeOf(record), out length);

            if (status == 0)
                return System.Text.Encoding.Unicode.GetString(record.Data.Take((int)record.DataLength).ToArray());

            return null;
        }


        private static void DeleteKey(SafeRegistryHandle handle, string key)
        {
            uint status = NtDeleteKey(handle);

            if (status != 0)
            {
                handle.Dispose();
                throw new IOException(String.Format("Unable to remove registry key: {0}. NTSTATUS: {1:X}", key, status));
            }

            Console.WriteLine("[+] Registry key {0} was successfully removed.", key);
        }


        private static SafeRegistryHandle CreateLink(string path)
        {
            OBJECT_ATTRIBUTES obj_attr = new OBJECT_ATTRIBUTES(path, ATTRIBUT_FLAG_CASE_INSENSITIVE);
            int disposition = 0;

            Console.WriteLine("[+] Creating registry key: {0}", path);

            IntPtr handle;
            uint status = NtCreateKey(out handle, KEY_LINK_ACCESS, obj_attr, 0, null, REG_OPTION_CREATE_LINK, out disposition);

            if (status == 0)
                return new SafeRegistryHandle(handle, true);

            throw new IOException(String.Format("Failure while creating registry key: {0}. NTSTATUS: {1:X}", path, status));
        }


        private static SafeRegistryHandle OpenKey(string path)
        {
            OBJECT_ATTRIBUTES obj_attr = new OBJECT_ATTRIBUTES(path, ATTRIBUT_FLAG_CASE_INSENSITIVE | ATTRIBUT_FLAG_OBJ_OPENLINK);

            IntPtr handle;
            uint status = NtOpenKeyEx(out handle, KEY_READ_DELETE_ACCESS, obj_attr, REG_OPTION_OPEN_LINK);

            if (status == 0)
                return new SafeRegistryHandle(handle, true);

            if (status == 0xC0000034)
                return null;

            throw new IOException(String.Format("Unable to open registry key: {0}. NTSTATUS: {1:X}", path, status));
        }


        public static string RegPathToNative(string path)
        {
            if (path[0] == '\\')
            {
                return path;
            }

            if (path.StartsWith(@"HKLM\"))
            {
                return regpath + @"Machine\" + path.Substring(5);
            }

            else if (path.StartsWith(@"HKU\"))
            {
                return regpath + @"User\" + path.Substring(4);
            }

            else if (path.StartsWith(@"HKCU\"))
            {
                return regpath + @"User\" + WindowsIdentity.GetCurrent().User.ToString() + @"\" + path.Substring(5);
            }

            throw new IOException("Registry path must be absolute or start with HKLM, HKU or HKCU");
        }
    }
}