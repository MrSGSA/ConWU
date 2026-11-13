using System.Text;

namespace ConWU.Mobile;

public static class CompactCodeInput
{
    public static string Normalize(string value)=>new(value.Where(c=>!char.IsWhiteSpace(c)&&c!='-'&&c is not (>= '\u2010' and <= '\u2015'))
        .Select(c=>char.ToUpperInvariant(c) switch{'O'=>'0','I' or 'L'=>'1',var next=>next}).ToArray());
    public static string Format(string value)
    {
        string text=Normalize(value);var result=new StringBuilder(text.Length+text.Length/4);
        for(int i=0;i<text.Length;i++){if(i>0&&i%4==0)result.Append('-');result.Append(text[i]);}return result.ToString();
    }
    public static (string Text,int Caret) Edit(string before,string after,int caret,int beforeCaret,int start,int removed,int added)
    {
        string raw=Normalize(after);int logical=Normalize(after[..Math.Clamp(caret,0,after.Length)]).Length;
        if(removed==1&&added==0&&start>=0&&start<before.Length&&before[start]=='-'){
            int index=beforeCaret>start?logical-1:logical;
            if(index>=0&&index<raw.Length){raw=raw.Remove(index,1);if(beforeCaret>start)logical--;}
        }
        string formatted=Format(raw);int position=Math.Clamp(logical+Math.Min(logical/4,3),0,formatted.Length);
        return(formatted,position);
    }
}
