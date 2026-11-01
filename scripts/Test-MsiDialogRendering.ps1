#requires -Version 7.0
param([Parameter(Mandatory)][string]$Msi,[Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$Msi=[IO.Path]::GetFullPath($Msi);$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
$meta=Get-Content -LiteralPath ($Msi+'.json') -Raw|ConvertFrom-Json
if(-not $meta.validationInstance){throw 'Only isolated validation MSI may be opened'}
New-Item -ItemType Directory -Path $OutputDirectory -Force|Out-Null
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;using System.Text;using System.Runtime.InteropServices;using System.Collections.Generic;
public static class MsiDialogCapture {
 public delegate bool EnumProc(IntPtr h,IntPtr p);
 [DllImport("user32.dll")]public static extern bool EnumWindows(EnumProc cb,IntPtr p);
 [DllImport("user32.dll")]public static extern bool EnumChildWindows(IntPtr parent,EnumProc cb,IntPtr p);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)]static extern int GetWindowText(IntPtr h,StringBuilder b,int size);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)]static extern int GetClassName(IntPtr h,StringBuilder b,int size);
 [DllImport("user32.dll")]public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")]public static extern bool GetWindowRect(IntPtr h,out Rect r);
 [DllImport("user32.dll")]public static extern bool PrintWindow(IntPtr h,IntPtr dc,uint flags);
 [DllImport("user32.dll")]public static extern bool SetWindowPos(IntPtr h,IntPtr after,int x,int y,int w,int height,uint flags);
 [DllImport("user32.dll")]public static extern IntPtr SendMessage(IntPtr h,uint message,IntPtr w,IntPtr l);
 public struct Rect {public int Left,Top,Right,Bottom;}
 public static string Text(IntPtr h){var b=new StringBuilder(4096);GetWindowText(h,b,b.Capacity);return b.ToString();}
 public static string Class(IntPtr h){var b=new StringBuilder(128);GetClassName(h,b,b.Capacity);return b.ToString();}
 public static IntPtr[] Windows(){var a=new List<IntPtr>();EnumWindows((h,p)=>{a.Add(h);return true;},IntPtr.Zero);return a.ToArray();}
 public static IntPtr[] Children(IntPtr parent){var a=new List<IntPtr>();EnumChildWindows(parent,(h,p)=>{a.Add(h);return true;},IntPtr.Zero);return a.ToArray();}
}
'@
$rows=[Collections.Generic.List[object]]::new()
function Capture([IntPtr]$Window,[string]$Name){
 $rect=[MsiDialogCapture+Rect]::new();[MsiDialogCapture]::GetWindowRect($Window,[ref]$rect)|Out-Null
 $bitmap=[Drawing.Bitmap]::new($rect.Right-$rect.Left,$rect.Bottom-$rect.Top);$g=[Drawing.Graphics]::FromImage($bitmap);$dc=$g.GetHdc()
 try{$ok=[MsiDialogCapture]::PrintWindow($Window,$dc,2)}finally{$g.ReleaseHdc($dc);$g.Dispose()}
 try{
  if(-not $ok){throw 'Native window capture failed'}
  $bitmap.Save((Join-Path $OutputDirectory ($Name+'.png')),[Drawing.Imaging.ImageFormat]::Png)
  foreach($child in [MsiDialogCapture]::Children($Window)){
   if([MsiDialogCapture]::Class($child) -ne 'Button' -or -not [MsiDialogCapture]::IsWindowVisible($child)){continue}
   $caption=[MsiDialogCapture]::Text($child);$r=[MsiDialogCapture+Rect]::new();[MsiDialogCapture]::GetWindowRect($child,[ref]$r)|Out-Null
   $colors=[Collections.Generic.HashSet[int]]::new();$dark=0
   for($y=[Math]::Max(0,$r.Top-$rect.Top+3);$y -lt [Math]::Min($bitmap.Height,$r.Bottom-$rect.Top-3);$y++){
    for($x=[Math]::Max(0,$r.Left-$rect.Left+3);$x -lt [Math]::Min($bitmap.Width,$r.Right-$rect.Left-3);$x++){
     $pixel=$bitmap.GetPixel($x,$y);$colors.Add($pixel.ToArgb())|Out-Null;if($pixel.R -lt 180 -and $pixel.G -lt 180 -and $pixel.B -lt 180){$dark++}
    }
   }
   $row=[ordered]@{page=$Name;button=$caption;colors=$colors.Count;inkPixels=$dark;status=$(if($dark -gt 10 -and $colors.Count -gt 4){'Pass'}else{'Fail'})};$rows.Add($row)
   if($row.status -ne 'Pass'){throw ('Button did not render: '+$caption)}
  }
 }finally{$bitmap.Dispose()}
}
$before=@(Get-CimInstance Win32_Service -Filter "Name='StreamLink-PersonalFeature'"|Select-Object Name,State,ProcessId)|ConvertTo-Json -Compress
$log=Join-Path $OutputDirectory 'dialog.log'
$process=Start-Process msiexec.exe -ArgumentList @('/i',('"'+$Msi+'"'),'/norestart','/l*v',('"'+$log+'"')) -WindowStyle Hidden -PassThru
$window=[IntPtr]::Zero
try{
 $deadline=[DateTime]::UtcNow.AddSeconds(40);$needle=$meta.validationInstance.Substring(0,8)
 while([DateTime]::UtcNow -lt $deadline){
  foreach($candidate in [MsiDialogCapture]::Windows()){if([MsiDialogCapture]::Text($candidate).Contains($needle) -and [MsiDialogCapture]::IsWindowVisible($candidate)){$window=$candidate;break}}
  if($window -ne [IntPtr]::Zero -and @([MsiDialogCapture]::Children($window)|Where-Object {[MsiDialogCapture]::Text($_) -match '安装 / 更新'}).Count){break}
  Start-Sleep -Milliseconds 200
 }
 if($window -eq [IntPtr]::Zero){throw 'No native installer dialog'}
 # Keep the installer away from the user's work. No cursor movement or hover
 # message is sent. PrintWindow asks the actual MSI dialog to render its tree.
 [MsiDialogCapture]::SetWindowPos($window,[IntPtr]::Zero,10000,10000,0,0,0x15)|Out-Null
 Start-Sleep -Milliseconds 350
 Capture $window 'welcome-before-hover'
 $accept=@([MsiDialogCapture]::Children($window)|Where-Object {[MsiDialogCapture]::Text($_) -like '*我已阅读*'})[0]
 [MsiDialogCapture]::SendMessage($accept,0xF5,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null
 Start-Sleep -Milliseconds 200;Capture $window 'welcome-enabled-before-hover'
 $license=@([MsiDialogCapture]::Children($window)|Where-Object {[MsiDialogCapture]::Text($_) -like '*查看许可*'})[0]
 # Post avoids blocking on a modal nested dialog.
 Add-Type '[System.Runtime.InteropServices.DllImport("user32.dll")]public static extern bool PostMessage(System.IntPtr h,uint m,System.IntPtr w,System.IntPtr l);' -Name MsiPost -Namespace Native
 [Native.MsiPost]::PostMessage($license,0xF5,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null
 Start-Sleep -Milliseconds 400
 $licenseWindow=@([MsiDialogCapture]::Windows()|Where-Object {[MsiDialogCapture]::Text($_) -eq '开源许可与第三方声明' -and [MsiDialogCapture]::IsWindowVisible($_)})[0]
 if($licenseWindow){Capture $licenseWindow 'license-before-hover';$back=@([MsiDialogCapture]::Children($licenseWindow)|Where-Object {[MsiDialogCapture]::Text($_) -like '*返回*'})[0];[Native.MsiPost]::PostMessage($back,0xF5,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null}
 $after=@(Get-CimInstance Win32_Service -Filter "Name='StreamLink-PersonalFeature'"|Select-Object Name,State,ProcessId)|ConvertTo-Json -Compress
 if($before -ne $after){throw 'Daily service changed'}
 [ordered]@{status='Pass';scope='Native Windows Installer PrintWindow render without hover; no installation executed';buttons=$rows.ToArray();dailyServiceUnchanged=$true;msi=$Msi}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $OutputDirectory 'result.json')
}finally{
 # Closing only the validation UI process cannot affect the daily service.
 if(-not $process.HasExited){Stop-Process -Id $process.Id -ErrorAction SilentlyContinue}
}
