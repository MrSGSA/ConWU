#requires -Version 7.0
# Native MSI bitmaps, drawn from the existing StreamLink vector mark and simple
# geometry. No downloaded artwork, embedded web engine, or runtime dependency.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory,[switch]$Preview,[string]$DisplayVersion='开发版本')
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
function Color([string]$hex){return [Drawing.ColorTranslator]::FromHtml($hex)}
function Fill($g,[string]$color,[single]$x,[single]$y,[single]$w,[single]$h){
 $brush=[Drawing.SolidBrush]::new((Color $color));try{$g.FillRectangle($brush,$x,$y,$w,$h)}finally{$brush.Dispose()}
}
function Mark($g,[single]$x,[single]$y,[single]$size){
 $saved=$g.Save();$g.TranslateTransform($x,$y);$g.ScaleTransform($size/256,$size/256)
 $g.TranslateTransform(128,128);$g.RotateTransform(45);$g.TranslateTransform(-128,-128)
 $path=[Drawing.Drawing2D.GraphicsPath]::new()
 $path.AddLine(96,76,76,76);$path.AddArc(24,76,104,104,270,-180);$path.AddLine(76,180,96,180);$path.StartFigure();$path.AddLine(160,76,180,76);$path.AddArc(128,76,104,104,270,180);$path.AddLine(180,180,160,180);$path.StartFigure();$path.AddLine(88,128,168,128)
 $pen=[Drawing.Pen]::new((Color '#7aa2f7'),24);$pen.StartCap='Round';$pen.EndCap='Round';$pen.LineJoin='Round'
 try{$g.DrawPath($pen,$path)}finally{$pen.Dispose();$path.Dispose();$g.Restore($saved)}
}
function Background($g,[int]$width,[int]$height,[int]$rail){
 Fill $g '#ffffff' 0 0 $width $height;Fill $g '#1a1b26' 0 0 $rail $height
 $shade=[Drawing.Drawing2D.LinearGradientBrush]::new([Drawing.Rectangle]::new(0,0,$rail,$height),(Color '#1a1b26'),(Color '#24283b'),[single]78)
 try{$g.FillRectangle($shade,0,0,$rail,$height)}finally{$shade.Dispose()}
 $clip=$g.Save();$g.SetClip([Drawing.Rectangle]::new(0,0,$rail,$height))
 Mark $g 12 22 68
 # A quiet point-to-point motif; deliberately contains no status or baked text.
 $pen=[Drawing.Pen]::new((Color '#414868'),[single]0.7)
 try{$g.DrawEllipse($pen,-70,170,233,233);$g.DrawEllipse($pen,-94,145,285,285);$g.DrawBezier($pen,30,230,71,160,100,272,135,203)}finally{$pen.Dispose()}
 foreach($point in @(@(30,230),@(135,203))){
  $ring=[Drawing.Pen]::new((Color '#bb9af7'),[single]0.6);$dot=[Drawing.SolidBrush]::new((Color '#7aa2f7'))
  try{$g.DrawEllipse($ring,$point[0]-6,$point[1]-6,12,12);$g.FillEllipse($dot,$point[0]-2,$point[1]-2,4,4)}finally{$ring.Dispose();$dot.Dispose()}
 }
 $g.Restore($clip)
}
function Bitmap([string]$name,[int]$width,[int]$height,[scriptblock]$paint){
 $bitmap=[Drawing.Bitmap]::new($width*3,$height*3,[Drawing.Imaging.PixelFormat]::Format24bppRgb)
 $g=[Drawing.Graphics]::FromImage($bitmap);$g.SmoothingMode='AntiAlias';$g.PixelOffsetMode='HighQuality';$g.ScaleTransform(3,3)
 try{& $paint $g;$bitmap.Save((Join-Path $OutputDirectory $name),[Drawing.Imaging.ImageFormat]::Bmp)}finally{$g.Dispose();$bitmap.Dispose()}
}
Bitmap 'background.bmp' 154 330 {param($g) Background $g 154 330 154}
# Fallback MSI disk-space/error dialogs retain their standard layout.
Bitmap 'dialog.bmp' 370 234 {param($g) Background $g 370 234 120}
Bitmap 'banner.bmp' 370 44 {param($g) $g.Clear((Color '#ffffff'));Fill $g '#1a1b26' 327 5 32 32;Mark $g 327 5 32}

if($Preview){
 # Render the same authored control rectangles without launching msiexec.
 # These PNGs are DESIGN PREVIEWS, not screenshots of an installed MSI dialog.
 $repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
 [xml]$ui=Get-Content -LiteralPath (Join-Path $repo 'installer/StreamLinkUI.wxs') -Raw
 [xml]$sidebar=Get-Content -LiteralPath (Join-Path $repo 'installer/Sidebar.wxi') -Raw
 $styles=@{};foreach($style in $ui.SelectNodes('//*[local-name()="TextStyle"]')){$styles[$style.Id]=$style}
 $format=[Drawing.StringFormat]::GenericTypographic.Clone();$format.Trimming='EllipsisCharacter';$format.HotkeyPrefix='Show'
 foreach($page in @(@{Id='SLWelcomeDlg';Name='welcome'},@{Id='SLProgressDlg';Name='progress'},@{Id='SLExitDlg';Name='complete'},@{Id='SLMaintenanceDlg';Name='maintenance'})){
  $bitmap=[Drawing.Bitmap]::new(984,780);$g=[Drawing.Graphics]::FromImage($bitmap);$g.SmoothingMode='AntiAlias';$g.TextRenderingHint='AntiAliasGridFit';$g.Clear((Color '#e1e2e7'))
  $framePen=[Drawing.Pen]::new((Color '#bec2d2'));$small=[Drawing.Font]::new('Microsoft YaHei UI',12,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
  $ink=[Drawing.SolidBrush]::new((Color '#565f89'))
  try{
   Fill $g '#ffffff' 32 24 920 700;$g.DrawRectangle($framePen,32,24,920,700)
   $g.DrawString('ConWU 安装',$small,$ink,48,36);$g.DrawString('×',$small,$ink,925,36)
   $g.TranslateTransform(32,64);$g.ScaleTransform(2,2);Background $g 460 330 154
   $dialog=$ui.SelectSingleNode('//*[local-name()="Dialog" and @Id="'+$page.Id+'"]')
   $controls=@($sidebar.DocumentElement.ChildNodes | Where-Object NodeType -eq Element)+@($dialog.ChildNodes | Where-Object NodeType -eq Element)
   foreach($control in $controls){
    if($control.LocalName -ne 'Control' -or $control.Type -eq 'Bitmap'){continue}
    if($control.Hidden -eq 'yes' -and $control.Id -ne 'Launch'){continue}
    $x=[single]$control.X;$y=[single]$control.Y;$w=[single]$control.Width;$h=[single]$control.Height
    $text=[string]$control.Text;$style=$styles['WixUI_Font_Normal']
    if($text -match '^\{\\([^}]+)\}'){$style=$styles[$Matches[1]];$text=$text.Substring($Matches[0].Length)}
    $text=$text.Replace('[STREAMLINK_DISPLAY_VERSION]',$DisplayVersion).Replace('[INSTALLFOLDER]','C:\Program Files\StreamLink\')
    if($control.Id -eq 'ActionText'){$text='正在配置后台网络服务'}
    $font=[Drawing.Font]::new($style.FaceName,([single]$style.Size*0.89),$(if($style.Bold -eq 'yes'){[Drawing.FontStyle]::Bold}else{[Drawing.FontStyle]::Regular}),[Drawing.GraphicsUnit]::Pixel)
    $brush=[Drawing.SolidBrush]::new([Drawing.Color]::FromArgb([int]$style.Red,[int]$style.Green,[int]$style.Blue))
    try{
     switch($control.Type){
      'Line' {$g.DrawLine($framePen,$x,$y,$x+$w,$y)}
      'PushButton' {
       Fill $g '#f1f2f6' $x $y $w $h
       $buttonPen=[Drawing.Pen]::new((Color $(if($control.Id -in 'Install','Finish'){'#34548a'}else{'#bec2d2'})),[single]0.65)
       try{$g.DrawRectangle($buttonPen,$x,$y,$w,$h)}finally{$buttonPen.Dispose()}
       $center=$format.Clone();$center.Alignment='Center';$center.LineAlignment='Center'
       try{$g.DrawString($text,$font,$brush,[Drawing.RectangleF]::new($x,$y,$w,$h),$center)}finally{$center.Dispose()}
      }
      'CheckBox' {
       Fill $g '#34548a' $x ($y+4) 9 9
       $check=[Drawing.Pen]::new([Drawing.Color]::White,[single]1)
       try{$g.DrawLines($check,[Drawing.PointF[]]@([Drawing.PointF]::new($x+2,$y+8),[Drawing.PointF]::new($x+4,$y+10),[Drawing.PointF]::new($x+7,$y+6)))}finally{$check.Dispose()}
       $g.DrawString($text,$font,$brush,[Drawing.RectangleF]::new($x+14,$y+2,$w-14,$h),$format)
      }
      'ProgressBar' {Fill $g '#e1e2e7' $x $y $w $h;Fill $g '#7aa2f7' $x $y ($w*.56) $h}
      'Text' {$g.DrawString($text,$font,$brush,[Drawing.RectangleF]::new($x,$y,$w,$h),$format)}
     }
    }finally{$brush.Dispose();$font.Dispose()}
   }
   $g.ResetTransform();$g.DrawString('设计预览 · 基于安装器布局生成，未运行安装程序',$small,$ink,32,746)
   $bitmap.Save((Join-Path $OutputDirectory ($page.Name+'.png')),[Drawing.Imaging.ImageFormat]::Png)
  }finally{$g.Dispose();$bitmap.Dispose();$framePen.Dispose();$small.Dispose();$ink.Dispose()}
 }
 $format.Dispose()
}
Write-Output $OutputDirectory
