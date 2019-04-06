using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace GetPriv
{
    class Program
    {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle, 
            bool DisableAllPrivileges, 
            ref _TOKEN_PRIVILEGES NewState, 
            uint NewStateLength, 
            IntPtr PreviousState,
            IntPtr PreviousStateLength);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(
            IntPtr ProcessHandle, 
            int acc, 
            ref IntPtr pHanldeToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(
            string host, 
            string name, 
            out _LUID pLuid);

        // https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_luid
        [StructLayout(LayoutKind.Sequential)]
        internal struct _LUID
        {
            internal UInt32 LowPart; // DWORD
            internal Int32 HighPart; // long
        }

        // https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_luid_and_attributes
        [StructLayout(LayoutKind.Sequential)]
        internal struct _LUID_AND_ATTRIBUTES
        {
            internal _LUID Luid;
            internal UInt32 Attributes; // DWORD
        }

        // https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_token_privilegess
        [StructLayout(LayoutKind.Sequential)]
        internal struct _TOKEN_PRIVILEGES
        {
            internal UInt32 PrivilegeCount; /* Always set this to 1 */
            internal _LUID_AND_ATTRIBUTES Privileges;
            /* This is supposed to be an array but I've found no samples of 
             * someone using it as an array in C-Sharp code. I couldn't get
             * it to work on my own. */
        }

        internal const int SE_PRIVILEGE_ENABLED    = 0x00000002;
        internal const int SE_PRIVILEGE_DISABLED   = 0x00000000;
        internal const int TOKEN_QUERY             = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        private static readonly string[] privileges = new string[] {
            "SeAssignPrimaryTokenPrivilege",  "SeAuditPrivilege", 
            "SeBackupPrivilege",              "SeChangeNotifyPrivilege", 
            "SeCreateGlobalPrivilege",        "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege",     "SeCreateSymbolicLinkPrivilege",
            "SeCreateTokenPrivilege",         "SeDebugPrivilege", 
            "SeEnableDelegationPrivilege",    "SeImpersonatePrivilege", 
            "SeIncreaseBasePriorityPrivilege","SeIncreaseQuotaPrivilege", 
            "SeIncreaseWorkingSetPrivilege",  "SeLoadDriverPrivilege",
            "SeLockMemoryPrivilege",          "SeMachineAccountPrivilege", 
            "SeManageVolumePrivilege",        "SeProfileSingleProcessPrivilege", 
            "SeRelabelPrivilege",             "SeRemoteShutdownPrivilege", 
            "SeRestorePrivilege",             "SeSecurityPrivilege", 
            "SeShutdownPrivilege",            "SeSyncAgentPrivilege", 
            "SeSystemEnvironmentPrivilege",   "SeSystemProfilePrivilege", 
            "SeSystemtimePrivilege",          "SeTakeOwnershipPrivilege", 
            "SeTcbPrivilege",                 "SeTimeZonePrivilege", 
            "SeTrustedCredManAccessPrivilege","SeUndockPrivilege"
            // "SeUnsolicitedInputPrivilege" // doesn't exist
        };

        public static void EnablePrivilege(string Privilege)
        {
            // Original code: https://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
            // GO Lang implementation: https://stackoverflow.com/a/55304787

            _TOKEN_PRIVILEGES tp = new _TOKEN_PRIVILEGES {
                PrivilegeCount = 1,
                Privileges = new _LUID_AND_ATTRIBUTES
                {
                    Attributes = SE_PRIVILEGE_ENABLED
                           // or SE_PRIVILEGE_DISABLED if you want to disable 
                           // all privileges.
                }
            };

            IntPtr ProcesHandle = Process.GetCurrentProcess().Handle;
            IntPtr TokenHandle = IntPtr.Zero;

            Console.WriteLine("Requesting: " + Privilege);
            if (OpenProcessToken(
                    ProcesHandle,                          // HANDLE  ProcessHandle
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, // DWORD   DesiredAccess
                    ref TokenHandle))                      // PHANDLE TokenHandle
            {
                if (LookupPrivilegeValue(
                        null,                    // LPCSTR lpSystemName
                        Privilege,               // LPCSTR lpName
                        out tp.Privileges.Luid)) // PLUID lpLuid
                {
                    if (AdjustTokenPrivileges(
                            TokenHandle,  // HANDLE            TokenHandle
                            false,        // BOOL              DisableAllPrivileges
                            ref tp,       // PTOKEN_PRIVILEGES NewState
                            0,            // DWORD             BufferLength
                            IntPtr.Zero,  // PTOKEN_PRIVILEGES PreviousState
                            IntPtr.Zero)) // PDWORD            ReturnLength
                    {
                        Console.WriteLine("Received : " + Privilege);
                        return;
                    }
                }
            }
            Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
        }

        static void Main(string[] args)
        {
            for (int i = 0; i < privileges.Length; i++)
            {
                Console.WriteLine("Press a key to get more privilege ...");
                Console.ReadKey();
                Console.WriteLine("");
                EnablePrivilege(privileges[i]);
            }
            Console.WriteLine("\r\nPress a key to exit program ...");
            Console.ReadKey();
        }
    }
}
