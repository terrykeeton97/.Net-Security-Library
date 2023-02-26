using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;

namespace Protect
{
    public class Security
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualProtect(IntPtr lpAddress, IntPtr dwSize, IntPtr flNewProtect, ref IntPtr lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr ZeroMemory(IntPtr addr, IntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void DebugActiveProcessStop(int processId);

        private struct PE
        {
            static public int[] SectionTabledWords = new int[] { 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x24 };
            static public int[] Bytes = new int[] { 0x1A, 0x1B };
            static public int[] Words = new int[] { 0x4, 0x16, 0x18, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x5C, 0x5E };
            static public int[] dWords = new int[] { 0x0, 0x8, 0xC, 0x10, 0x16, 0x1C, 0x20, 0x28, 0x2C, 0x34, 0x3C, 0x4C, 0x50, 0x54, 0x58, 0x60, 0x64, 0x68, 0x6C, 0x70, 0x74, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x11C };
        }

        /// <summary>
        /// This method checks whether a debugger is present in the current process,
        /// and if so, stops it from attaching to the process. Returns a boolean value indicating whether a debugger was detected and stopped.
        /// Disabling debuggers can make debugging your own code more difficult, and may not prevent all types of debugging or reverse engineering.
        /// Use with caution and carefully consider the risks and benefits of this method.
        /// </summary>
        /// <returns>True if a debugger was detected and stopped, false otherwise.</returns>
        public static bool DisableDebugger()
        {
            bool isDebuggerPresent = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);

            if (isDebuggerPresent)
            {
                DebugActiveProcessStop(Process.GetCurrentProcess().Id);
                return true;
            }

            return false;
        }

        /// <summary>
        /// This method erases a section of memory at the specified address, 
        /// by changing the memory protection, zeroing out the memory, and then restoring the original protection. 
        /// </summary>
        /// <param name="address">The address of the section of memory to erase.</param>
        /// <param name="size">The size of the section of memory to erase, in bytes.</param>
        public static void EraseSection(IntPtr address, int size)
        {
            IntPtr sz = (IntPtr)size;
            IntPtr dwOld = default;
            VirtualProtect(address, sz, (IntPtr)0x40, ref dwOld);
            ZeroMemory(address, sz);
            IntPtr temp = default;
            VirtualProtect(address, sz, dwOld, ref temp);
        }

        /// <summary>
        /// Detect the presence of certain web sniffing tools in the current process, 
        /// by checking for the presence of specific modules in the process's loaded modules. 
        /// </summary>
        /// <returns>True if the current process contains a web sniffing tool, otherwise false.</returns>
        public static bool WebSniffers()
        {
            if (GetModuleHandle("HTTPDebuggerBrowser.dll") != IntPtr.Zero ||
                GetModuleHandle("FiddlerCore4.dll") != IntPtr.Zero ||
                GetModuleHandle("RestSharp.dll") != IntPtr.Zero ||
                GetModuleHandle("Titanium.Web.Proxy.dll") != IntPtr.Zero)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Check whether the current process is being debugged by a debugger, 
        /// by calling the CheckRemoteDebuggerPresent function and examining the return value. 
        /// </summary>
        /// <returns>True if the current process is being debugged, otherwise false.</returns>
        public static bool AntiDebug()
        {
            bool isDebuggerPresent = true;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
            if (isDebuggerPresent)
                return true;

            return false;
        }

        /// <summary>
        /// Detect whether the current process is running under the Sandboxie software, 
        /// by checking for the presence of the "SbieDll.dll" module in the process's loaded modules. 
        /// </summary>
        /// <returns>True if the current process is running under Sandboxie, otherwise false.</returns>
        public static bool Sandboxie()
        {
            if (GetModuleHandle("SbieDll.dll").ToInt32() != 0)
                return true;

            return false;
        }

        /// <summary>
        /// Emulation(); performs a short delay of 500 milliseconds using Thread.Sleep, 
        /// then checks whether the delay was accurately achieved using Environment.TickCount. 
        /// If the delay was not accurate, it returns true, otherwise it returns false. 
        /// This method is useful for checking the accuracy of the system clock and the Thread.Sleep method.
        /// </summary>
        /// <returns>True if the delay was not accurate, otherwise false.</returns>
        public static bool Emulation()
        {
            long tickCount = Environment.TickCount;
            Thread.Sleep(500);
            long tickCount2 = Environment.TickCount;
            if ((tickCount2 - tickCount) < 500L)
                return true;

            return false;
        }

        /// <summary>
        /// Detect whether the current system is running on a virtual machine.
        /// </summary>
        /// <returns>True if a virtual machine is detected, otherwise false.</returns>
        public static bool DetectVM()
        {
            using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
            using (ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get())
                foreach (ManagementBaseObject managementBaseObject in managementObjectCollection)
                    if ((managementBaseObject["Manufacturer"].ToString().ToLower() == "microsoft corporation" && managementBaseObject["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL")) || managementBaseObject["Manufacturer"].ToString().ToLower().Contains("vmware") || managementBaseObject["Model"].ToString() == "VirtualBox")
                        return true;

            foreach (ManagementBaseObject managementBaseObject2 in new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_VideoController").Get())
                if (managementBaseObject2.GetPropertyValue("Name").ToString().Contains("VMware") && managementBaseObject2.GetPropertyValue("Name").ToString().Contains("VBox"))
                    return true;

            return false;
        }

        /// <summary>
        /// This method performs low-level memory manipulation to erase certain sections of a process's memory to make it more difficult to dump. 
        /// </summary>
        /// <returns>True if the memory manipulation was successful, otherwise false.</returns>
        public static bool AntiDump()
        {
            try
            {
                var process = Process.GetCurrentProcess();
                var base_address = process.MainModule.BaseAddress;
                var dwpeheader = Marshal.ReadInt32(base_address + 0x3C);
                var wnumberofsections = Marshal.ReadInt16(base_address + dwpeheader + 0x6);

                EraseSection(base_address, 30);

                for (int i = 0; i < PE.dWords.Length; i++)
                    EraseSection(base_address + dwpeheader + PE.dWords[i], 4);

                for (int i = 0; i < PE.Words.Length; i++)
                    EraseSection(base_address + dwpeheader + PE.Words[i], 2);

                for (int i = 0; i < PE.Bytes.Length; i++)
                    EraseSection(base_address + dwpeheader + PE.Bytes[i], 1);

                int x = 0;
                int y = 0;

                while (x <= wnumberofsections)
                {
                    if (y == 0)
                        EraseSection(base_address + dwpeheader + 0xFA + (0x28 * x) + 0x20, 2);

                    EraseSection(base_address + dwpeheader + 0xFA + (0x28 * x) + PE.SectionTabledWords[y], 4);

                    y++;

                    if (y == PE.SectionTabledWords.Length)
                    {
                        x++;
                        y = 0;
                    }
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// This method checks whether the file "dnSpy.xml" exists in the user's AppData\Roaming folder, and returns a boolean value indicating whether it was found.
        /// If the file exists, this suggests that the program dnSpy is or has been installed on the system.
        /// This information can be useful for detecting potential security risks, identifying software dependencies, or other purposes.
        /// </summary>
        /// <returns>True if the file was found, false otherwise.</returns>
        public static bool CheckDnSpyInstallation()
        {
            string filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "dnSpy", "dnSpy.xml");
            return File.Exists(filePath);
        }

        /// <summary>
        /// This method checks whether the directory "C:\Users\[username]\AppData\Roaming\Hex-Rays" exists, and returns a boolean value indicating whether it was found.
        /// If the directory exists, this suggests that IDA Pro has been installed on the system, since this folder is created during the installation process.
        /// This information can be useful for detecting potential security risks, identifying software dependencies, or other purposes.
        /// </summary>
        /// <returns>True if the directory was found, false otherwise.</returns>
        public static bool CheckIDAProInstallation()
        {
            string directoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Hex-Rays");
            return Directory.Exists(directoryPath);
        }
    }
}