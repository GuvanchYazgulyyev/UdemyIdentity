using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.ViewModels
{    // Rol Atama işlemi
    // Roleri Siralar CheckBox için
    public class RoleAssignViewModel
    {
        public string RoleId { get; set; }
        public string RoleName { get; set; }
        public bool Exist { get; set; }
    }
}
