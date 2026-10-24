using System;

namespace WebAppNetCore.Emergency.Tests
{
    public sealed class TestClock : TimeProvider
    {
        public DateTimeOffset Value { get; set; } = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        public override DateTimeOffset GetUtcNow() => Value;
        public void Advance(int seconds)
        {
            Value = Value.AddSeconds(seconds);
        }
    }
}
