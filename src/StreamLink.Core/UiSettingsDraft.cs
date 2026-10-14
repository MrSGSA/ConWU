namespace StreamLink.Core;

// Pure editing state, separate from WinForms focus and service configuration.
// This type can be tested without a desktop, pipe, driver or administrator token.
public sealed class UiSettingsDraft
{
    UiStatusDto? latest;
    string baseName="",baseLevel="info";
    public string DeviceName {get;private set;}="";
    public string LogLevel {get;private set;}="info";
    public bool Initialized=>latest!=null;
    public bool NameDirty=>Initialized&&DeviceName!=baseName;
    public bool LevelDirty=>Initialized&&LogLevel!=baseLevel;
    public bool Dirty=>NameDirty||LevelDirty;
    public bool NameConflict=>NameDirty&&latest!.DeviceName!=baseName&&latest.DeviceName!=DeviceName;
    public bool LevelConflict=>LevelDirty&&latest!.LogLevel!=baseLevel&&latest.LogLevel!=LogLevel;
    public bool Conflict=>NameConflict||LevelConflict;
    public void EditName(string value)=>DeviceName=value;
    public void EditLevel(string value)=>LogLevel=value;
    public void Observe(UiStatusDto status)
    {
        bool nameDirty=NameDirty,levelDirty=LevelDirty;
        latest=status;
        if(!nameDirty||DeviceName==status.DeviceName)DeviceName=baseName=status.DeviceName;
        if(!levelDirty||LogLevel==status.LogLevel)LogLevel=baseLevel=status.LogLevel;
    }
    public void Reset(UiStatusDto status)
    {
        latest=status;DeviceName=baseName=status.DeviceName;LogLevel=baseLevel=status.LogLevel;
    }
    public void Discard(){if(latest!=null)Reset(latest);}
    public UiConfigPatch CreatePatch()
    {
        if(latest==null)throw new InvalidOperationException("尚未读取后台设置");
        if(Conflict)throw new IOException("后台设置已改变，未覆盖草稿；请撤销草稿并核对最新设置后重新编辑");
        return new(NameDirty?DeviceName.Trim():null,LevelDirty?LogLevel:null,
            NameDirty&&latest.SettingsPatchVersion>=2?baseName:null,
            LevelDirty&&latest.SettingsPatchVersion>=2?baseLevel:null);
    }
}
