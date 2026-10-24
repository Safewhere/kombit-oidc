using System;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class EmergencyFault : Exception
    {
        public int Status { get; }
        public string Code { get; }
        public EmergencyFault(int status, string code, Exception inner = null) : base(code, inner) { Status = status; Code = code; }
    }
}
