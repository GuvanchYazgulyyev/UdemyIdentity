using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.Models
{
    public class Yetenek
    {
        [Key]
        public string ID { get; set; }
        public string YetenekAd { get; set; }
        public string YetenekSeviye { get; set; }
    }
}
