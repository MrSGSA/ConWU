#requires -Version 7.0
param([Parameter(Mandatory)][string]$OutputRoot,[Parameter(Mandatory)][string]$DependencyCache,[string]$Version='1.0.0-aq1-personal.1')
# AQ-1 supersedes the research-driver personal packaging contract.
& (Join-Path $PSScriptRoot 'Package-AqPersonal.ps1') -OutputRoot $OutputRoot -DependencyCache $DependencyCache -Version $Version