using System.Globalization;
using System.Text.RegularExpressions;

namespace StreamLink.Core;
public sealed record ReleaseVersion(int Major,int Minor,int Patch,string PreRelease="",string Build=""):IComparable<ReleaseVersion>
{
    public bool Stable=>PreRelease.Length==0;
    public static bool TryParse(string? text,out ReleaseVersion? version)
    {
        version=null;if(text==null||text.Length>256)return false;if(text.StartsWith('v'))text=text[1..];
        var match=Regex.Match(text,@"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$",RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(100));
        if(!match.Success||!int.TryParse(match.Groups[1].Value,NumberStyles.None,CultureInfo.InvariantCulture,out int major)||!int.TryParse(match.Groups[2].Value,NumberStyles.None,CultureInfo.InvariantCulture,out int minor)||!int.TryParse(match.Groups[3].Value,NumberStyles.None,CultureInfo.InvariantCulture,out int patch))return false;
        string pre=match.Groups[4].Value;if(pre.Split('.').Any(p=>p.Length>1&&p.All(char.IsAsciiDigit)&&p[0]=='0'))return false;
        version=new(major,minor,patch,pre,match.Groups[5].Value);return true;
    }
    public int CompareTo(ReleaseVersion? other)
    {
        if(other==null)return 1;foreach(int n in new[]{Major.CompareTo(other.Major),Minor.CompareTo(other.Minor),Patch.CompareTo(other.Patch)})if(n!=0)return n;
        if(Stable||other.Stable)return Stable==other.Stable?0:Stable?1:-1;
        var a=PreRelease.Split('.');var b=other.PreRelease.Split('.');for(int i=0;i<Math.Min(a.Length,b.Length);i++){
            bool numericA=a[i].All(char.IsAsciiDigit),numericB=b[i].All(char.IsAsciiDigit);int result=numericA&&numericB?(a[i].Length==b[i].Length?string.CompareOrdinal(a[i],b[i]):a[i].Length.CompareTo(b[i].Length)):numericA!=numericB?(numericA?-1:1):string.CompareOrdinal(a[i],b[i]);if(result!=0)return result;
        }return a.Length.CompareTo(b.Length);
    }
    public static ReleaseVersion? Latest(IEnumerable<(string Tag,bool Draft,bool Prerelease)> feed,bool includePreview)
        =>feed.Where(x=>!x.Draft&&(includePreview||!x.Prerelease)).Select(x=>TryParse(x.Tag,out var v)?v:null).Where(v=>v!=null&&(includePreview||v.Stable)).OrderDescending().FirstOrDefault();
    public override string ToString()=>$"{Major}.{Minor}.{Patch}"+(Stable?"":"-"+PreRelease)+(Build.Length==0?"":"+"+Build);
}
