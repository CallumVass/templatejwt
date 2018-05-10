using System.Collections.Generic;

namespace StarterWebJwt.ViewModels
{
    public class ValidationError
    {
        public ValidationError()
        {
            this.Errors = new List<string>();
        }

        public string PropertyName { get; set; }
        public IEnumerable<string> Errors { get; set; }
    }
}
