using System.Security.Cryptography;
using System.Text.Json;

static partial class Program
{
    static async Task ProbabilityModel(string output)
    {
        const int count = 10000, range = 65536;
        var seeds = new HashSet<int>();
        while (seeds.Count < count) seeds.Add(RandomNumberGenerator.GetInt32(int.MaxValue));
        var rows = new List<object>();
        foreach (var (sources, guesses) in new[] { (8, 120), (8, 96), (32, 256), (64, 1024) }) {
            int hits = 0;
            foreach (int seed in seeds) {
                var random = new Random(seed);
                var mappings = new HashSet<int>(); var targets = new HashSet<int>();
                while (mappings.Count < sources) mappings.Add(random.Next(range));
                while (targets.Count < guesses) targets.Add(random.Next(range));
                if (mappings.Overlaps(targets)) hits++;
            }
            double misses = 1;
            for (int i = 0; i < guesses; i++) misses *= (double)(range - sources - i) / (range - i);
            double exact = 1 - misses, observed = (double)hits / count, z = 1.959963984540054;
            double denominator = 1 + z * z / count, center = (observed + z * z / (2 * count)) / denominator;
            double radius = z * Math.Sqrt(observed * (1 - observed) / count + z * z / (4.0 * count * count)) / denominator;
            Check(Math.Abs(observed - exact) < 6 * Math.Sqrt(exact * (1 - exact) / count), "independent uniform intersection samples agree with the finite-space model within six standard errors");
            rows.Add(new { sources, guesses, range, independentSeeds = count, intersections = hits, proportion = observed,
                wilson95Lower = center - radius, wilson95Upper = center + radius, exact, approximation = 1 - Math.Exp(-(double)sources * guesses / range),
                executionBudget = sources <= 32 && guesses <= 256 ? "within experiment size only; other admission rules still apply" : "cost comparison only; NOT an executable exploration profile" });
        }
        await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { status = "Pass", checks, runtime = Environment.Version.ToString(), seeds, rows,
            scope = "math-only independent uniform port-set intersection; no sockets, NAT, filtering, timing, authentication, PMTU or product connectivity success probability" }, new JsonSerializerOptions { WriteIndented = true }));
    }
}
