# Deterministic rendering of the repository's vector mark; no image service.
param([string]$Destination=(Join-Path $PSScriptRoot '../src/StreamLink.App/Assets/streamlink.ico'))
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$images=[Collections.Generic.List[byte[]]]::new()
$sizes=@(16,20,24,32,40,48,64,128,256)
foreach($size in $sizes){
 $bitmap=[Drawing.Bitmap]::new($size,$size,[Drawing.Imaging.PixelFormat]::Format32bppArgb)
 $g=[Drawing.Graphics]::FromImage($bitmap);$g.SmoothingMode='AntiAlias';$g.PixelOffsetMode='HighQuality';$g.Clear([Drawing.Color]::Transparent);$g.ScaleTransform($size/256.0,$size/256.0)
 $tile=[Drawing.Drawing2D.GraphicsPath]::new();foreach($arc in @(@(0,0,112,112,180),@(144,0,112,112,270),@(144,144,112,112,0),@(0,144,112,112,90))){$tile.AddArc($arc[0],$arc[1],$arc[2],$arc[3],$arc[4],90)};$tile.CloseFigure()
 $brush=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#1a1b26'));$g.FillPath($brush,$tile)
 $path=[Drawing.Drawing2D.GraphicsPath]::new();$path.AddLine(96,76,76,76);$path.AddArc(24,76,104,104,270,-180);$path.AddLine(76,180,96,180);$path.StartFigure();$path.AddLine(160,76,180,76);$path.AddArc(128,76,104,104,270,180);$path.AddLine(180,180,160,180);$path.StartFigure();$path.AddLine(88,128,168,128)
 $pen=[Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#7aa2f7'),24);$pen.StartCap='Round';$pen.EndCap='Round';$pen.LineJoin='Round';$g.DrawPath($pen,$path)
 $memory=[IO.MemoryStream]::new();$bitmap.Save($memory,[Drawing.Imaging.ImageFormat]::Png);$images.Add($memory.ToArray())
 $memory.Dispose();$pen.Dispose();$path.Dispose();$brush.Dispose();$tile.Dispose();$g.Dispose();$bitmap.Dispose()
}
$Destination=[IO.Path]::GetFullPath($Destination);$stream=[IO.File]::Create($Destination);$writer=[IO.BinaryWriter]::new($stream)
try{$writer.Write([uint16]0);$writer.Write([uint16]1);$writer.Write([uint16]$sizes.Count);$offset=6+16*$sizes.Count
 for($i=0;$i -lt $sizes.Count;$i++){$writer.Write([byte]($sizes[$i]%256));$writer.Write([byte]($sizes[$i]%256));$writer.Write([byte]0);$writer.Write([byte]0);$writer.Write([uint16]1);$writer.Write([uint16]32);$writer.Write([uint32]$images[$i].Length);$writer.Write([uint32]$offset);$offset+=$images[$i].Length}
 foreach($data in $images){$writer.Write($data)}
}finally{$writer.Dispose()}
Write-Output $Destination
