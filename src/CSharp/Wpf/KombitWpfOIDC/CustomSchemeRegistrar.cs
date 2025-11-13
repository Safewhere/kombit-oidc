using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Win32;
using Serilog;

namespace KombitWpfOIDC;

/// <summary>
/// Handles registration of custom URI scheme (wpfoidc://) in Windows Registry
/// </summary>
public static class CustomSchemeRegistrar
{
    private const string SchemeName = "wpfoidc";
    private const string FriendlyName = "Kombit WPF OIDC Protocol";

    /// <summary>
    /// Registers the custom URI scheme in Windows Registry
    /// </summary>
    /// <returns>True if registration was successful, false otherwise</returns>
    public static bool RegisterScheme()
    {
        try
        {
            // Check if running as administrator
            if (!IsAdministrator())
            {
                return RegisterSchemeForCurrentUser();
            }

            return RegisterSchemeForAllUsers();
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to register custom URI scheme");
            return false;
        }
    }

    /// <summary>
    /// Checks if the custom URI scheme is already registered
    /// </summary>
    public static bool IsSchemeRegistered()
    {
        try
        {
            // Check HKEY_CURRENT_USER first
            using var userKey = Registry.CurrentUser.OpenSubKey($@"Software\Classes\{SchemeName}");
            if (userKey != null)
            {
                return true;
            }

            // Check HKEY_CLASSES_ROOT (system-wide)
            using var classesKey = Registry.ClassesRoot.OpenSubKey(SchemeName);
            return classesKey != null;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to check if scheme is registered");
            return false;
        }
    }

    /// <summary>
    /// Unregisters the custom URI scheme
    /// </summary>
    public static bool UnregisterScheme()
    {
        try
        {
            // Remove from HKEY_CURRENT_USER
            Registry.CurrentUser.DeleteSubKeyTree($@"Software\Classes\{SchemeName}", false);

            // Try to remove from HKEY_CLASSES_ROOT if admin
            if (IsAdministrator())
            {
                Registry.ClassesRoot.DeleteSubKeyTree(SchemeName, false);
            }

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to unregister custom URI scheme");
            return false;
        }
    }

    private static bool RegisterSchemeForCurrentUser()
    {
        try
        {
            var exePath = Process.GetCurrentProcess().MainModule?.FileName
               ?? Environment.ProcessPath
                    ?? throw new InvalidOperationException("Cannot determine executable path");

            using var key = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{SchemeName}");
            key.SetValue("", $"URL:{FriendlyName}");
            key.SetValue("URL Protocol", "");

            using var defaultIcon = key.CreateSubKey("DefaultIcon");
            defaultIcon.SetValue("", $"\"{exePath}\",0");

            using var command = key.CreateSubKey(@"shell\open\command");
            command.SetValue("", $"\"{exePath}\" \"%1\"");

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to register scheme for current user");
            return false;
        }
    }

    private static bool RegisterSchemeForAllUsers()
    {
        try
        {
            var exePath = Process.GetCurrentProcess().MainModule?.FileName
               ?? Environment.ProcessPath
              ?? throw new InvalidOperationException("Cannot determine executable path");

            using var key = Registry.ClassesRoot.CreateSubKey(SchemeName);
            key.SetValue("", $"URL:{FriendlyName}");
            key.SetValue("URL Protocol", "");

            using var defaultIcon = key.CreateSubKey("DefaultIcon");
            defaultIcon.SetValue("", $"\"{exePath}\",0");

            using var command = key.CreateSubKey(@"shell\open\command");
            command.SetValue("", $"\"{exePath}\" \"%1\"");

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to register scheme system-wide");
            return false;
        }
    }

    private static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Gets the registered executable path for the scheme
    /// </summary>
    public static string? GetRegisteredExecutablePath()
    {
        try
        {
            // Check HKEY_CURRENT_USER first
            using var userKey = Registry.CurrentUser.OpenSubKey($@"Software\Classes\{SchemeName}\shell\open\command");
            if (userKey?.GetValue("") is string userValue)
            {
                return ExtractExecutablePath(userValue);
            }

            // Check HKEY_CLASSES_ROOT
            using var classesKey = Registry.ClassesRoot.OpenSubKey($@"{SchemeName}\shell\open\command");
            if (classesKey?.GetValue("") is string classesValue)
            {
                return ExtractExecutablePath(classesValue);
            }

            return null;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get registered executable path");
            return null;
        }
    }

    private static string ExtractExecutablePath(string commandValue)
    {
        // Command format: "C:\Path\To\App.exe" "%1"
        var firstQuote = commandValue.IndexOf('"');
        var secondQuote = commandValue.IndexOf('"', firstQuote + 1);

        if (firstQuote >= 0 && secondQuote > firstQuote)
        {
            return commandValue.Substring(firstQuote + 1, secondQuote - firstQuote - 1);
        }

        return commandValue.Split(' ')[0].Trim('"');
    }
}
