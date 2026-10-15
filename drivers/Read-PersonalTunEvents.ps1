function Read-PersonalTunEvents([string]$LogName,[datetime]$StartTime,[int[]]$Ids=@()) {
 try {
  $log=Get-WinEvent -ListLog $LogName -ErrorAction Stop
  if(-not $log.IsEnabled){throw 'Event log is disabled; no security setting changed'}
  $filter=@{LogName=$LogName;StartTime=$StartTime};if($Ids.Count){$filter.Id=$Ids}
  try{$events=@(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop|Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message)}
  catch{if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){$events=@()}else{throw}}
  return @{status='Observed';log=$LogName;startTime=$StartTime;events=$events;error=$null}
 }catch{return @{status='Unknown';log=$LogName;startTime=$StartTime;events=@();error=$_.Exception.Message}}
}
