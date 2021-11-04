using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace UdemyIdentity.ViewModels
{

    // Rolleri Atamak işin kullanılır
    public class RoleViewModel
    {
        [Display(Name="Rol İsimi")]
        [Required(ErrorMessage ="Rol Gereklidir!!!")]
        public string Name { get; set; }

        public string Id { get; set; }
    }
}
