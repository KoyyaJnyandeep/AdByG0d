export type TechniqueId = 0|1|2|3|4|5|6|7|8|9|10|11|12|13|'auto'

export interface ObfuscationTechnique {
  id: TechniqueId
  name: string
  shortName: string
  level: 'MEDIUM'|'HIGH'|'MAX'|'GOD'
  tag: string
  desc: string
}

export const LEVEL_COLORS: Record<string, string> = {
  MEDIUM: '#fbbf24',
  HIGH:   '#fb923c',
  MAX:    '#f43f5e',
  GOD:    '#a855f7',
}

export const OBFUSCATION_TECHNIQUES: ObfuscationTechnique[] = [
  {
    id: 'auto', name: 'Auto-Rotate', shortName: 'AUTO', level: 'MAX',
    tag: 'hash-determin.',
    desc: 'Deterministically rotates technique per-command via hash — every command gets a different layer',
  },
  {
    id: 0, name: 'Base64 UTF-8 IEX', shortName: 'B64-IEX', level: 'HIGH',
    tag: 'encoding',
    desc: 'UTF-8 base64 encoded, decoded via System.Text.Encoding::UTF8 + mixed-case IEX chain',
  },
  {
    id: 1, name: 'XOR Runtime Decrypt', shortName: 'XOR', level: 'HIGH',
    tag: 'key-XOR runtime',
    desc: 'Each byte XOR-encrypted with random key, decrypted byte-by-byte via ForEach pipeline at runtime',
  },
  {
    id: 2, name: 'CharArray ScriptBlock', shortName: 'CHR[]', level: 'HIGH',
    tag: 'char codes',
    desc: 'ASCII char-code array fed into ScriptBlock::Create() — zero string literals in source',
  },
  {
    id: 3, name: 'Reverse IEX', shortName: 'REV', level: 'HIGH',
    tag: 'string reverse',
    desc: 'Command stored reversed, re-assembled at runtime via negative index slice and piped to IEX',
  },
  {
    id: 4, name: 'Format String', shortName: 'FMT', level: 'MEDIUM',
    tag: '-f operator',
    desc: 'Command exploded into variable-length chunks, reassembled via PowerShell -f format operator',
  },
  {
    id: 5, name: 'EnvVar Char Extract', shortName: 'ENV', level: 'HIGH',
    tag: 'env extraction',
    desc: 'Individual characters surgically extracted from $env:ComSpec and $PSHome by index',
  },
  {
    id: 6, name: 'Double Encode', shortName: 'DBL', level: 'MAX',
    tag: 'nested b64+chr',
    desc: 'The base64 decoder expression itself is char-array encoded — two-pass decode required to read',
  },
  {
    id: 7, name: 'VarConcat Split', shortName: 'VCAT', level: 'HIGH',
    tag: 'hex var names',
    desc: 'Command fragmented across hex-named variables, concatenated at runtime via IEX',
  },
  {
    id: 8, name: 'Tick+MixCase+B64', shortName: 'T+M+B', level: 'MAX',
    tag: 'triple layer',
    desc: 'Backtick insertion + mixed-case applied first, the obfuscated result then base64-encoded',
  },
  {
    id: 9, name: 'UTF-16LE Encoded', shortName: 'UTF16', level: 'HIGH',
    tag: 'unicode b64',
    desc: 'UTF-16LE base64 matches native PowerShell -EncodedCommand wire format exactly',
  },
  {
    id: 10, name: 'SecureString BSTR', shortName: 'SECSTR', level: 'GOD',
    tag: 'Marshal BSTR',
    desc: 'Command wrapped through SecureString/BSTR decode path for collector compatibility testing',
  },
  {
    id: 11, name: 'Runspace Isolation', shortName: 'RSPACE', level: 'GOD',
    tag: 'reflection API',
    desc: 'Runs through an isolated PowerShell Runspace to compare collector behavior across execution contexts',
  },
  {
    id: 12, name: 'Add-Type C# JIT', shortName: 'CSJIT', level: 'GOD',
    tag: '.NET compile',
    desc: 'Uses an inline C# helper through Add-Type for lab execution-path comparison',
  },
  {
    id: 13, name: 'MemStream Reader', shortName: 'MSTR', level: 'MAX',
    tag: 'IO stream',
    desc: 'Base64 bytes loaded into MemoryStream and StreamReader before execution for wrapper compatibility testing',
  },
]

function hashCode(str: string): number {
  let h = 0
  for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0
  return Math.abs(h)
}

function toUtf8Bytes(str: string): number[] {
  const b: number[] = []
  for (let i = 0; i < str.length; i++) {
    const cc = str.charCodeAt(i)
    if (cc < 0x80) { b.push(cc) }
    else if (cc < 0x800) { b.push(0xc0 | (cc >> 6), 0x80 | (cc & 0x3f)) }
    else { b.push(0xe0 | (cc >> 12), 0x80 | ((cc >> 6) & 0x3f), 0x80 | (cc & 0x3f)) }
  }
  return b
}

function toUtf16LeBytes(str: string): number[] {
  const b: number[] = []
  for (let i = 0; i < str.length; i++) {
    const cc = str.charCodeAt(i)
    b.push(cc & 0xff, (cc >> 8) & 0xff)
  }
  return b
}

function b64(bytes: number[]): string {
  let bin = ''
  for (const byte of bytes) bin += String.fromCharCode(byte)
  return btoa(bin)
}

function b64utf8(str: string) { return b64(toUtf8Bytes(str)) }
function b64utf16(str: string) { return b64(toUtf16LeBytes(str)) }

function mixedCase(str: string): string {
  return str.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join('')
}

function tickInsert(cmd: string): string {
  return cmd.replace(/\b([A-Z][a-z]+)-([A-Z][A-Za-z]+)\b/g, (_m, verb, noun) => {
    const v = verb.split('').reduce((a: string, c: string, i: number) =>
      a + c + (i < verb.length - 1 && i % 2 === 1 ? '`' : ''), '')
    return `${v}-${noun}`
  })
}

// 0 · Base64 UTF-8 IEX
function t0(cmd: string): string {
  return `iEx([SYstEm.tExT.EnCODiNG]::UTF8.GeTSTRiNg([SYstEm.CoNvErT]::fRoMBaSe64StRiNg('${b64utf8(cmd)}')))`
}

// 1 · XOR runtime decrypt
function t1(cmd: string, key: number): string {
  const xored = toUtf8Bytes(cmd).map(b => b ^ key)
  const hk = '0x' + key.toString(16).padStart(2, '0').toUpperCase()
  return `iEx(-JoIn(@(${xored.join(',')}) | FoReAcH-oBjEcT {[cHAr]($_ -bXoR ${hk})}))`
}

// 2 · CharArray ScriptBlock::Create
function t2(cmd: string): string {
  const codes = Array.from(cmd).map(c => c.charCodeAt(0))
  return `&([sCriPtBLoCk]::cReAtE((-JoIn([cHaR[]]@(${codes.join(',')})))))`
}

// 3 · Reverse-string IEX
function t3(cmd: string): string {
  const rev = cmd.split('').reverse().join('')
  return `$_rS='${rev.replace(/'/g, "''")}';iEx(-JoIn$_rS[-1..-${cmd.length}])`
}

// 4 · Format-string assembly
function t4(cmd: string, seed: number): string {
  const sizes = [3, 5, 2, 6, 4, 3, 7, 2]
  let i = 0; let ci = 0; let si = seed % sizes.length
  const chunks: string[] = []; const ph: string[] = []
  while (i < cmd.length) {
    const sz = sizes[si % sizes.length]
    chunks.push(`'${cmd.slice(i, i + sz).replace(/'/g, "''")}'`)
    ph.push(`{${ci}}`)
    i += sz; ci++; si++
  }
  return `iEx(('${ph.join('')}'-f${chunks.join(',')}))`
}

// 5 · Env-var char extraction
function t5(cmd: string): string {
  const ENV: Record<string, [string, number]> = {
    C: ['$env:ComSpec', 0],  W: ['$env:ComSpec', 3],  i: ['$env:ComSpec', 10],
    n: ['$env:ComSpec', 11], d: ['$env:ComSpec', 13], o: ['$env:ComSpec', 14],
    w: ['$env:ComSpec', 16], s: ['$env:ComSpec', 18], y: ['$env:ComSpec', 19],
    e: ['$env:ComSpec', 20], m: ['$env:ComSpec', 21], '3': ['$env:ComSpec', 23],
    '2': ['$env:ComSpec', 24], c: ['$env:ComSpec', 25], x: ['$env:ComSpec', 26],
  }
  const parts = Array.from(cmd).map(ch =>
    ENV[ch] ? `${ENV[ch][0]}[${ENV[ch][1]}]` : `[cHaR]${ch.charCodeAt(0)}`
  )
  const groups: string[] = []
  for (let gi = 0; gi < parts.length; gi += 8) groups.push(parts.slice(gi, gi + 8).join('+'))
  return `iEx(${groups.join('+\n      ')})`
}

// 6 · Double-encode (base64 inner, char-array outer)
function t6(cmd: string): string {
  const inner = `[SYstEm.tExT.EnCODiNG]::UTF8.GeTSTRiNg([SYstEm.CoNvErT]::fRoMBaSe64StRiNg('${b64utf8(cmd)}'))`
  const codes = Array.from(inner).map(c => c.charCodeAt(0))
  return `iEx((-JoIn([cHaR[]]@(${codes.join(',')}))))`
}

// 7 · VarConcat split (hex-named vars)
function t7(cmd: string, seed: number): string {
  const sz = 4 + (seed % 3)
  const parts: string[] = []; const vars: string[] = []
  let i = 0; let vi = 0
  while (i < cmd.length) {
    const chunk = cmd.slice(i, i + sz)
    const vn = `_${((seed * 7 + vi * 13) % 0x7fff).toString(16)}`
    parts.push(`$${vn}='${chunk.replace(/'/g, "''")}'`)
    vars.push(`$${vn}`)
    i += sz; vi++
  }
  return `${parts.join(';')};iEx(${vars.join('+')})`
}

// 8 · Layered: tick + mixed-case → base64
function t8(cmd: string): string {
  return t0(tickInsert(mixedCase(cmd)))
}

// 9 · UTF-16LE encoded (matches -EncodedCommand format)
function t9(cmd: string): string {
  const b = b64utf16(cmd)
  return `&([sCriPtBLoCk]::cReAtE([SYstEm.tExT.EnCODiNG]::UniCoDe.GeTStRiNg([SYstEm.CoNvErT]::fRoMBaSe64StRiNg('${b}'))))`
}

// 10 · SecureString BSTR marshal — looks like credential handling to AV
function t10(cmd: string): string {
  const enc = b64utf8(cmd)
  return [
    `$_b='${enc}'`,
    `$_ss=ConvertTo-SecureString $_b -AsPlainText -Force`,
    `$_p=[SYstEm.RuNtImE.InTeRoPSeRvIcEs.MaRsHaL]::SecureStringToBSTR($_ss)`,
    `$_d=[SYstEm.RuNtImE.InTeRoPSeRvIcEs.MaRsHaL]::PtrToStringAuto($_p)`,
    `[SYstEm.RuNtImE.InTeRoPSeRvIcEs.MaRsHaL]::ZeroFreeBSTR($_p)`,
    `iEx([SYstEm.tExT.EnCODiNG]::UTF8.GeTSTRiNg([SYstEm.CoNvErT]::fRoMBaSe64StRiNg($_d)))`,
  ].join(';')
}

// 11 · Runspace isolation — bypasses transcript + AMSI + SBL hooks
function t11(cmd: string): string {
  const enc = b64utf8(cmd)
  // Join with semicolons (PS statement separator) instead of backtick-n.
  // Avoids minifier converting the string to a template literal with unescaped backticks.
  return [
    "$_rs=[SYstEm.MaNaGeMeNt.AuToMaTiOn.RuNsPaCeS.RuNsPaCeFaCtOrY]::CreateRunspace()",
    "$_rs.Open()",
    "$_ps=[SYstEm.MaNaGeMeNt.AuToMaTiOn.PoWeRsHeLl]::Create()",
    "$_ps.Runspace=$_rs",
    `[void]$_ps.AddScript([SYstEm.tExT.EnCODiNG]::UTF8.GeTSTRiNg([SYstEm.CoNvErT]::fRoMBaSe64StRiNg('${enc}')))`,
    "$_ps.Invoke()|OuT-StRiNg",
    "$_rs.Close();$_rs.Dispose();$_ps.Dispose()",
  ].join(";")
}

// 12 · Add-Type C# JIT — CLR execution-path comparison
function t12(cmd: string): string {
  const enc = b64utf8(cmd)
  const cls = '_' + Math.abs(hashCode(cmd) % 0xFFFF).toString(16).toUpperCase()
  const typedef = [
    "using System;",
    "using System.Management.Automation;",
    "using System.Collections.ObjectModel;",
    `public class ${cls}{`,
    "  public static Collection<PSObject> E(string c){",
    "    using(PowerShell p=PowerShell.Create()){return p.AddScript(c).Invoke();}",
    "  }",
    "}",
  ].join('')
  // Inline if-block so semicolon join works cleanly for all statements.
  return [
    `if(-not([SYstEm.MaNaGeMeNt.AuToMaTiOn.PSTypeName]'${cls}').Type){Add-Type -TypeDefinition '${typedef.replace(/'/g, "''")}' -Language CSharp}`,
    `[${cls}]::E([SYstEm.tExT.EnCODiNG]::UTF8.GeTSTRiNg([SYstEm.CoNvErT]::fRoMBaSe64StRiNg('${enc}')))|OuT-StRiNg`,
  ].join(";")
}

// 13 · MemoryStream + StreamReader IEX
function t13(cmd: string): string {
  const enc = b64utf8(cmd)
  return [
    `$_bArr=[SYstEm.CoNvErT]::fRoMBaSe64StRiNg('${enc}')`,
    `$_ms=New-Object SYstEm.IO.MemoryStream(,$_bArr)`,
    `$_sr=New-Object SYstEm.IO.StreamReader($_ms,[SYstEm.tExT.EnCODiNG]::UTF8)`,
    `try{iEx($_sr.ReadToEnd())}finally{$_sr.Dispose();$_ms.Dispose()}`,
  ].join(';')
}

export function obfuscateCommand(cmd: string, technique: TechniqueId = 'auto'): string {
  if (!cmd.trim()) return cmd
  const h = hashCode(cmd)
  const key = (h % 180) + 40
  const resolved: 0|1|2|3|4|5|6|7|8|9|10|11|12|13 =
    technique === 'auto' ? (h % 14) as 0|1|2|3|4|5|6|7|8|9|10|11|12|13 : technique

  switch (resolved) {
    case 0:  return t0(cmd)
    case 1:  return t1(cmd, key)
    case 2:  return t2(cmd)
    case 3:  return t3(cmd)
    case 4:  return t4(cmd, h)
    case 5:  return t5(cmd)
    case 6:  return t6(cmd)
    case 7:  return t7(cmd, h)
    case 8:  return t8(cmd)
    case 9:  return t9(cmd)
    case 10: return t10(cmd)
    case 11: return t11(cmd)
    case 12: return t12(cmd)
    case 13: return t13(cmd)
    default: return t0(cmd)
  }
}

// Script-level obfuscation for PS1 collector
export function obfuscateScript(script: string): string {
  let out = script

  const cmdletMap: [RegExp, string][] = [
    [/\bInvoke-Expression\b/g,  'iEx'],
    [/\bWrite-Host\b/g,         'WrItE-HoSt'],
    [/\bGet-Date\b/g,           'GeT-DaTe'],
    [/\bNew-Item\b/g,           'NeW-ITeM'],
    [/\bStart-Job\b/g,          'StArT-JoB'],
    [/\bWait-Job\b/g,           'WaIt-JoB'],
    [/\bReceive-Job\b/g,        'ReCeIvE-JoB'],
    [/\bRemove-Job\b/g,         'ReMoVe-JoB'],
    [/\bStop-Job\b/g,           'StOp-JoB'],
    [/\bConvertTo-Json\b/g,     'CoNvErTtO-JSoN'],
    [/\bOut-File\b/g,           'OuT-FiLe'],
    [/\bCompress-Archive\b/g,   'CoMpReSs-ArChIvE'],
    [/\bRemove-Item\b/g,        'ReMoVe-ItEm'],
    [/\bJoin-Path\b/g,          'JoIn-PaTh'],
    [/\bOut-Null\b/g,           'OuT-NuLl'],
    [/\bOut-String\b/g,         'OuT-StRiNg'],
    [/\bFormat-List\b/g,        'FoRmAt-LiSt'],
    [/\bSelect-Object\b/g,      'SeLeCt-ObJeCt'],
    [/\bForEach-Object\b/g,     'FoReAcH-ObJeCt'],
    [/\bWhere-Object\b/g,       'WhErE-ObJeCt'],
    [/\bNew-Object\b/g,         'NeW-ObJeCt'],
    [/\bSet-StrictMode\b/g,     'SeT-StRiCtMoDe'],
    [/\bGet-ChildItem\b/g,      'GeT-ChIlDiTeM'],
    [/\bAdd-Type\b/g,           'AdD-TyPe'],
    [/\bConvertFrom-Json\b/g,   'CoNvErTfRoM-JSoN'],
  ]
  for (const [re, rep] of cmdletMap) out = out.replace(re, rep)

  // Rename internal variables
  out = out
    .replace(/\$moduleOutputs\b/g, '$_m0dOut')
    .replace(/\$cmdResults\b/g,    '$_cR3s')
    .replace(/\$ModuleName\b/g,    '$_mNam3')
    .replace(/\$timestamp\b/g,     '$_tS')
    .replace(/\$runDir\b/g,        '$_rD')
    .replace(/\$zipName\b/g,       '$_zN')
    .replace(/\$zipPath\b/g,       '$_zP')
    .replace(/\$manifest\b/g,      '$_mNf')
    // $ErrorActionPreference and $ProgressPreference are PS automatic variables —
    // renaming them creates dummy variables that PS ignores, breaking error/progress
    // handling silently. Leave them as-is.

  return out
}

// Per-command obfuscation for the collector script job blocks.
// Only single-expression techniques (t0/t1/t2/t9) are used here — the output is
// wrapped in $_result = (...) 2>&1 in the script template, so multi-statement
// techniques like t13 (try/finally chain) or t10/t11/t12 (semicolon-joined) are
// invalid inside () and must not appear in auto rotation.
export function obfuscateJobCommand(subIE: string, technique: TechniqueId = 'auto'): string {
  const h = hashCode(subIE)
  const key = (h % 180) + 40
  const resolved = technique === 'auto'
    ? ([0, 1, 2, 9] as const)[h % 4]
    : technique as 0|1|2|3|4|5|6|7|8|9|10|11|12|13

  switch (resolved) {
    case 0:  return t0(subIE)
    case 1:  return t1(subIE, key)
    case 2:  return t2(subIE)
    case 9:  return t9(subIE)
    default: return t0(subIE)
  }
}
