using System.Text.Json;

// Fixture verdict only. None of these conditions change transport algorithms.
sealed record TraversalVerdictInput(bool ExpectedNoDirectPath, bool InfrastructureReady,
    bool CheckExecuted, string TransportOutcome, string SourceExpectation, bool BusinessComplete,
    bool MeasureLoad, bool LoadPass, bool CleanupComplete, string Failure);
sealed record TraversalVerdict(string ScenarioVerdict, int ExitCode, string FunctionalStatus,
    string FailureCategory, string SourceExpectation)
{
    public static TraversalVerdict Evaluate(TraversalVerdictInput i)
    {
        bool functional = i.InfrastructureReady && i.BusinessComplete && i.SourceExpectation != "Fail" && i.Failure.Length == 0;
        // A deadline without a prepared check is not a transport negative.
        bool negative = i.ExpectedNoDirectPath && i.InfrastructureReady && i.CheckExecuted &&
            i.TransportOutcome == "NoDirectPathWithinBudget" && !i.BusinessComplete &&
            i.Failure.Length == 0 && i.CleanupComplete;
        bool passed = i.ExpectedNoDirectPath ? negative : functional && (!i.MeasureLoad || i.LoadPass) && i.CleanupComplete;
        string category = !i.CleanupComplete ? "Cleanup" : !i.InfrastructureReady ? "Infrastructure" :
            i.Failure.Length != 0 ? "RuntimeOrAuthentication" : i.SourceExpectation == "Fail" ? "SourceExpectation" :
            !i.BusinessComplete ? "TransportOrBusiness" : i.MeasureLoad && !i.LoadPass ? "Quality" : "None";
        return new(passed ? "Pass" : "Fail", passed ? 0 : 1, functional ? "Pass" : "Fail", negative ? "ExpectedTransportFailure" : category, i.SourceExpectation);
    }
    public static void Test(string output)
    {
        var good = new TraversalVerdictInput(false, true, true, "BusinessUsable", "NotApplicable", true, false, false, true, "");
        var cases = new[] {
            ("public TCP: no HostFactory required", good, true),
            ("source mismatch despite business delivery", good with { SourceExpectation="Fail" }, false),
            ("negative after actual prepared transport deadline", good with {ExpectedNoDirectPath=true, BusinessComplete=false, TransportOutcome="NoDirectPathWithinBudget"}, true),
            ("negative missing DLL", good with {ExpectedNoDirectPath=true, InfrastructureReady=false, BusinessComplete=false, Failure="MissingBinary"}, false),
            ("negative coordination/authorization failure", good with {ExpectedNoDirectPath=true, BusinessComplete=false, Failure="ControlUnavailable"}, false),
            ("negative before any prepared check", good with {ExpectedNoDirectPath=true, BusinessComplete=false, CheckExecuted=false, TransportOutcome="NoDirectPathWithinBudget"}, false),
            ("negative cleanup failure", good with {ExpectedNoDirectPath=true, BusinessComplete=false, TransportOutcome="NoDirectPathWithinBudget", CleanupComplete=false}, false),
            ("quality requested but not passed", good with {MeasureLoad=true}, false),
            ("positive load qualified", good with {MeasureLoad=true,LoadPass=true}, true),
            ("unexpected positive in negative scenario", good with {ExpectedNoDirectPath=true}, false),
            ("partial business", good with {BusinessComplete=false}, false),
            ("source expectation correct announcement", good with {SourceExpectation="Pass"}, true)
        };
        var rows=cases.Select(c=> { var v=Evaluate(c.Item2); if ((v.ExitCode==0)!=c.Item3 || (v.ScenarioVerdict=="Pass")!=c.Item3) throw new Exception(c.Item1); return new { test=c.Item1,expected=c.Item3,result=v }; }).ToArray();
        File.WriteAllText(output,JsonSerializer.Serialize(new {status="Pass",checks=rows.Length,scope="Table-driven fixture verdict; no NAT/driver claim",rows},new JsonSerializerOptions{WriteIndented=true}));
    }
}
