<#
.SYNOPSIS
    Reverse Tutor 一键验证 demo（32 位 ELF / ida.exe 版）。

.DESCRIPTION
    这个脚本不依赖 DSH GUI，直接把插件的整条流水线跑一遍，让你在两分钟内看到
    结果对不对：

      1. 环境自检        —— 编译器、目标架构、产物目录
      2. 生成一道新题     —— 真正的 ELF32 i386 crackme，写进产物根目录
                              （默认 ~/reverse-tutor，可用 DSH_REVERSE_TUTOR_ROOT 覆盖）
      3. 观察（IDA 看到的东西）—— file / readelf / 反汇编
      4. 裁判（确定性验证）—— 正确答案 => true，错答案 => false
      5. 提示阶梯        —— 答错一次，hint 等级 +1
      6. 列出磁盘上所有题 —— 每一道都能直接用 ida.exe 打开

    脚本会打印「正确答案」，因为它是给你（出题人）验证用的，不是给学生用的。

.PARAMETER Template
    题目模板：xor-loop | strcmp | arithmetic | branch | function-args

.PARAMETER Difficulty
    beginner | intermediate

.PARAMETER SessionId
    学习状态用的会话 id，影响 hint 等级和技能分。

.EXAMPLE
    .\demo.ps1
    .\demo.ps1 -Template strcmp -Difficulty intermediate
#>
[CmdletBinding()]
param(
    [ValidateSet('xor-loop', 'strcmp', 'arithmetic', 'branch', 'function-args')]
    [string]$Template = 'xor-loop',

    [ValidateSet('beginner', 'intermediate')]
    [string]$Difficulty = 'beginner',

    [string]$SessionId = 'demo',

    # IDA Pro 32 位版可执行文件路径；默认从 PATH 解析。
    [string]$IdaPath = 'ida.exe'
)

$ErrorActionPreference = 'Stop'
$cli = Join-Path $PSScriptRoot 'lib\cli.js'

if (-not (Test-Path $cli)) {
    Write-Host 'lib/cli.js 不存在，先跑一次构建：' -ForegroundColor Yellow
    Write-Host '  npm run build' -ForegroundColor Yellow
    exit 1
}

function Section([string]$Title) {
    Write-Host ''
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
}

function Run([string[]]$Arguments) {
    # `verify` exits 1 for a rejected candidate, which is a legitimate result here and
    # must not abort the demo under $ErrorActionPreference = 'Stop'.
    & node $cli @Arguments 2>&1
    $global:LASTEXITCODE = 0
}

# ---------------------------------------------------------------- 1. 环境 ----
Section '1 / 6  环境自检'
Run @('info')
Write-Host '目标：ELF32 i386（32 位），可用 IDA Pro 32 位版（ida.exe）打开。' -ForegroundColor Green
Run @('templates')

# ------------------------------------------------------------ 2. 生成新题 ----
Section "2 / 6  生成新题：$Template / $Difficulty"
$rendered = Run @('render', $Template, $Difficulty)
$rendered | Write-Host

$tutorRoot = if ($env:DSH_REVERSE_TUTOR_ROOT) { $env:DSH_REVERSE_TUTOR_ROOT } else { Join-Path $HOME 'reverse-tutor' }
$challengesDir = Join-Path $tutorRoot 'challenges'

Write-Host '正在编译……' -ForegroundColor DarkGray
$buildOutput = Run @('build', $Template, $Difficulty)
$picked = $buildOutput |
    Where-Object { $_ -match '^[a-z-]+-\d{8}-\d{6}-[0-9a-f]{4}$' } |
    Select-Object -Last 1
if (-not $picked) {
    Write-Host ($buildOutput | Out-String)
    Write-Host '构建失败，停止。' -ForegroundColor Red
    exit 1
}
$picked = $picked.Trim()

Write-Host ''
Write-Host "题目 id：$picked" -ForegroundColor Green
Run @('show', $picked)

# --------------------------------------------------- 3. 观察（IDA 视角） ----
Section '3 / 6  观察：文件事实与关键函数（IDA Pro 会看到的同一份数据）'
Run @('inspect', $picked)
Run @('disasm', $picked)

# --------------------------------------------------- 4. 确定性裁判 ----
Section '4 / 6  判定：正确答案与错误答案'

$secretLine = Run @('show-secret', $picked) |
    Where-Object { $_ -match '^\s*accepted value:\s*(.+)$' } |
    Select-Object -First 1
if ($secretLine) {
    $secret = ([regex]::Match($secretLine, '^\s*accepted value:\s*(.+)$')).Groups[1].Value.Trim()
}
else {
    # The command's plain form prints the value alone on its own line.
    $secret = (Run @('show-secret', $picked) |
        Where-Object { $_.Trim() -ne '' } |
        Select-Object -Last 1).Trim()
}
if ([string]::IsNullOrWhiteSpace($secret)) {
    Write-Host '取不到正确答案，停止。' -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host "正确答案（出题人可见）：$secret" -ForegroundColor Yellow
Write-Host ''
Write-Host '提交正确答案……' -ForegroundColor DarkGray
Run @('verify', $picked, $secret)

Write-Host ''
Write-Host '提交错误答案……' -ForegroundColor DarkGray
$wrong = $secret.Substring(0, $secret.Length - 1) + $(if ($secret[-1] -eq 'a') { 'b' } else { 'a' })
Run @('verify', $picked, $wrong)

# ------------------------------------------------------- 5. 提示阶梯 ----
Section '5 / 6  提示阶梯与学习状态'
Run @('state', $SessionId)
Write-Host '（真正作答时会通过 reverse_submit 工具推进 hint 等级；这里是 CLI 视角。）'

# --------------------------------------------------------- 6. 清单 ----
Section "6 / 6  $tutorRoot 上的全部题目"
Run @('list')

Write-Host ''
Write-Host '在 IDA 中打开：' -ForegroundColor Green
Write-Host ('  {0} "{1}"' -f $IdaPath, (Join-Path $challengesDir "$picked\challenge")) -ForegroundColor Green
Write-Host ''
Write-Host '在 DSH 里做这道题：直接说「给我一道 32 位 XOR 题」。' -ForegroundColor Green
